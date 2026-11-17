using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.Data.SqlClient;
using SecurityHealth.Api;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = ScanSubmission.MaxBytes);
builder.Services.Configure<IISServerOptions>(options => options.MaxRequestBodySize = ScanSubmission.MaxBytes);
builder.Services.AddAuthentication(IISDefaults.AuthenticationScheme);
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Ingest", policy => policy.RequireAuthenticatedUser().RequireAssertion(context =>
    {
        var users = builder.Configuration.GetSection("Ingestion:AllowedUsers").Get<string[]>() ?? [];
        var groups = builder.Configuration.GetSection("Ingestion:AllowedGroups").Get<string[]>() ?? [];
        return users.Any(user => !string.IsNullOrWhiteSpace(user) &&
                   string.Equals(user, context.User.Identity?.Name, StringComparison.OrdinalIgnoreCase)) ||
               groups.Any(group => !string.IsNullOrWhiteSpace(group) && context.User.IsInRole(group));
    }));
});
builder.Services.AddSingleton<IScanStore>(_ =>
    new SqlScanStore(builder.Configuration.GetConnectionString("Scans")
        ?? throw new InvalidOperationException("ConnectionStrings:Scans is required.")));

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapPost("/api/v1/scans", async (HttpContext context, IScanStore store, ILogger<Program> logger) =>
{
    var correlationId = context.TraceIdentifier;
    IResult Error(int status, string message) =>
        Results.Json(new { error = message, correlationId }, statusCode: status);

    if (!context.Request.IsHttps)
        return Error(400, "HTTPS is required.");
    if (!context.Request.HasJsonContentType())
        return Error(415, "Content-Type must be application/json.");

    try
    {
        if (context.Request.ContentLength > ScanSubmission.MaxBytes)
            return Error(413, "Request is too large.");
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted)) != 0)
        {
            if (buffer.Length + read > ScanSubmission.MaxBytes)
                return Error(413, "Request is too large.");
            await buffer.WriteAsync(chunk.AsMemory(0, read), context.RequestAborted);
        }
        var bytes = buffer.ToArray();
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        if (!ScanSubmission.TryCreate(document.RootElement, context.User.Identity?.Name, out var submission))
            return Error(400, "Invalid submission or unsupported schema version.");
        var result = await store.SaveAsync(submission!, SHA256.HashData(bytes), context.RequestAborted);
        if (result == SaveResult.Conflict)
            return Error(409, "Submission ID has already been used with different content or identity.");
        return Results.Json(new
        {
            submissionId = submission!.Id,
            status = result == SaveResult.Created ? "created" : "duplicate",
            correlationId
        }, statusCode: result == SaveResult.Created ? 201 : 200);
    }
    catch (JsonException)
    {
        return Error(400, "Invalid JSON.");
    }
    catch (BadHttpRequestException ex) when (ex.StatusCode == 413)
    {
        return Error(413, "Request is too large.");
    }
    catch (SqlException ex)
    {
        // SQL exception messages can contain connection and submitted data.
        logger.LogError("Scan persistence failed. SQL number {Number}; correlation {CorrelationId}.",
            ex.Number, correlationId);
        return Error(503, "Storage is unavailable.");
    }
}).RequireAuthorization("Ingest");
app.Run();

public partial class Program;
