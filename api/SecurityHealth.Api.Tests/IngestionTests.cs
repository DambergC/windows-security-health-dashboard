using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SecurityHealth.Api;
using Xunit;

namespace SecurityHealth.Api.Tests;

public sealed class IngestionTests
{
    internal static string Payload(Guid? id = null, string computer = "PC-042") => JsonSerializer.Serialize(new
    {
        TransportVersion = 1,
        SubmissionId = id ?? Guid.NewGuid(),
        SubmittedAtUtc = "2026-11-17T19:00:00Z",
        Snapshot = new
        {
            SchemaVersion = 1,
            ToolVersion = "1.5.0",
            Computer = computer,
            ScanTime = "2026-11-17 19:00:00",
            LookbackDays = "7",
            CollectedBy = @"CORP\operator",
            Sections = new { Meta = new { Kind = "props", Props = new { ComputerName = computer } } }
        }
    });

    [Theory]
    [InlineData(null, false, 401)]
    [InlineData(@"CORP\outsider", false, 403)]
    [InlineData(@"CORP\collector", false, 201)]
    [InlineData(@"CORP\group-member", false, 201)]
    [InlineData(@"CORP\collector", true, 403)]
    public async Task EnforcesAuthenticationAndExplicitAuthorization(string? user, bool noAllowlist, int status)
    {
        using var factory = new ApiFactory(noAllowlist);
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        if (user is not null) client.DefaultRequestHeaders.Add("X-Test-User", user);
        using var response = await Post(client, Payload());
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(status == 201 ? 1 : 0, factory.Store.Calls);
    }

    [Theory]
    [InlineData("TransportVersion", "1", "99")]
    [InlineData("SchemaVersion", "1", "99")]
    [InlineData("LookbackDays", "\"7\"", "\"91\"")]
    [InlineData("SubmittedAtUtc", "\"2026-11-17T19:00:00Z\"", "\"2026-11-17T19:00:00+02:00\"")]
    public async Task RejectsInvalidContract(string field, string original, string replacement)
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        var body = Payload().Replace($"\"{field}\":{original}", $"\"{field}\":{replacement}");
        using var response = await Post(client, body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(0, factory.Store.Calls);
        Assert.Contains("correlationId", await response.Content.ReadAsStringAsync());
    }

    [Theory]
    [InlineData("{")]
    [InlineData("{}")]
    public async Task RejectsMalformedOrIncompleteJson(string body)
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        using var response = await Post(client, body);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task RejectsDuplicatePropertiesAndInvalidSectionShape()
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        foreach (var body in new[]
        {
            Payload().Replace("\"TransportVersion\":1", "\"TransportVersion\":1,\"transportVersion\":1"),
            Payload().Replace("\"Kind\":\"props\"", "\"Kind\":\"other\""),
            Payload().Replace("\"ComputerName\":\"PC-042\"", "\"ComputerName\":true"),
            Payload(computer: new string('x', 256))
        })
        {
            using var response = await Post(client, body);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        }
        Assert.Equal(0, factory.Store.Calls);
    }

    [Fact]
    public async Task RejectsHttpAndIncorrectContentType()
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        using var http = await client.PostAsync("http://localhost/api/v1/scans",
            new StringContent(Payload(), Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, http.StatusCode);
        using var plain = await client.PostAsync("/api/v1/scans", new StringContent(Payload()));
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, plain.StatusCode);
        Assert.Equal(0, factory.Store.Calls);
    }

    [Theory]
    [InlineData(SaveResult.Created, 201, "created")]
    [InlineData(SaveResult.Duplicate, 200, "duplicate")]
    [InlineData(SaveResult.Conflict, 409, null)]
    public async Task AcknowledgesOnlyCommittedStoreResults(SaveResult result, int status, string? expected)
    {
        using var factory = new ApiFactory();
        factory.Store.Result = result;
        using var client = AuthorizedClient(factory);
        var id = Guid.NewGuid();
        using var response = await Post(client, Payload(id));
        Assert.Equal(status, (int)response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.False(string.IsNullOrEmpty(json.RootElement.GetProperty("correlationId").GetString()));
        if (expected is not null)
        {
            Assert.Equal(id, json.RootElement.GetProperty("submissionId").GetGuid());
            Assert.Equal(expected, json.RootElement.GetProperty("status").GetString());
        }
        Assert.Equal(@"CORP\collector", factory.Store.Last?.Uploader);
    }

    [Theory]
    [InlineData(0, 201)]
    [InlineData(1, 413)]
    public async Task EnforcesExactByteLimit(int excess, int status)
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        var payload = Payload();
        // JSON permits trailing whitespace; this tests the actual byte boundary.
        var body = payload + new string(' ', ScanSubmission.MaxBytes - Encoding.UTF8.GetByteCount(payload) + excess);
        using var response = await Post(client, body);
        Assert.Equal(status, (int)response.StatusCode);
    }

    [Fact]
    public async Task AcceptsNormalizedRowsIncludingEmptySections()
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        var body = JsonNode.Parse(Payload())!;
        body["Snapshot"]!["Sections"]!["Events"] = JsonSerializer.SerializeToNode(new
        {
            Kind = "rows",
            Rows = new[] { new { Detail = "line one\nline two", Id = "1121" } }
        });
        body["Snapshot"]!["Sections"]!["Empty"] = JsonSerializer.SerializeToNode(new
        {
            Kind = "rows",
            Rows = Array.Empty<object>()
        });
        using var response = await Post(client, body.ToJsonString());
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        using var stored = JsonDocument.Parse(factory.Store.Last!.SnapshotJson);
        Assert.Equal("line one\nline two",
            stored.RootElement.GetProperty("Sections").GetProperty("Events").GetProperty("Rows")[0]
                .GetProperty("Detail").GetString());
    }

    [Fact]
    public async Task EnforcesLimitWhenContentLengthIsUnknown()
    {
        using var factory = new ApiFactory();
        using var client = AuthorizedClient(factory);
        using var content = new UnknownLengthContent(new byte[ScanSubmission.MaxBytes + 1]);
        content.Headers.ContentType = new("application/json");
        using var response = await client.PostAsync("/api/v1/scans", content);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Equal(0, factory.Store.Calls);
    }

    [Theory]
    [InlineData("Server=sql;Integrated Security=false;Encrypt=true;TrustServerCertificate=false")]
    [InlineData("Server=sql;Integrated Security=true;Encrypt=false;TrustServerCertificate=false")]
    [InlineData("Server=sql;Integrated Security=true;Encrypt=true;TrustServerCertificate=true")]
    public void RejectsInsecureProductionSqlConfiguration(string connectionString) =>
        Assert.Throws<InvalidOperationException>(() => new SqlScanStore(connectionString));

    [Theory]
    [InlineData("Mandatory")]
    [InlineData("Strict")]
    [InlineData("true")]
    public void AcceptsEncryptedIntegratedSqlConfiguration(string encryption) =>
        Assert.NotNull(new SqlScanStore(
            $"Server=sql.corp.example;Integrated Security=true;Encrypt={encryption};TrustServerCertificate=false"));

    private static HttpClient AuthorizedClient(ApiFactory factory)
    {
        var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        client.DefaultRequestHeaders.Add("X-Test-User", @"CORP\collector");
        return client;
    }

    private static Task<HttpResponseMessage> Post(HttpClient client, string body) =>
        client.PostAsync("/api/v1/scans", new StringContent(body, Encoding.UTF8, "application/json"));
}

internal sealed class ApiFactory(bool noAllowlist = false, IScanStore? persistence = null) : WebApplicationFactory<Program>
{
    public FakeStore Store { get; } = new();
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(
            noAllowlist ? [] : new Dictionary<string, string?>
            {
                ["Ingestion:AllowedUsers:0"] = @"CORP\collector",
                ["Ingestion:AllowedGroups:0"] = @"CORP\ingesters"
            }));
        builder.ConfigureServices(services =>
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Test";
                options.DefaultChallengeScheme = "Test";
                options.DefaultForbidScheme = "Test";
            }).AddScheme<AuthenticationSchemeOptions, TestAuthentication>("Test", _ => { });
            services.RemoveAll<IScanStore>();
            services.AddSingleton(persistence ?? Store);
        });
    }
}

internal sealed class UnknownLengthContent(byte[] bytes) : HttpContent
{
    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        stream.WriteAsync(bytes).AsTask();

}

internal sealed class TestAuthentication(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var name = Request.Headers["X-Test-User"].ToString();
        if (string.IsNullOrEmpty(name)) return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new(ClaimTypes.Name, name) };
        if (name == @"CORP\group-member") claims.Add(new(ClaimTypes.Role, @"CORP\ingesters"));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(
            new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name)), Scheme.Name)));
    }
}

internal sealed class FakeStore : IScanStore
{
    public int Calls { get; private set; }
    public ScanSubmission? Last { get; private set; }
    public SaveResult Result { get; set; }
    public Task<SaveResult> SaveAsync(ScanSubmission submission, byte[] hash, CancellationToken cancellationToken)
    {
        Calls++;
        Last = submission;
        return Task.FromResult(Result);
    }
}
