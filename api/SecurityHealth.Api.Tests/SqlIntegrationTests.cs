using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net;
using Microsoft.Data.SqlClient;
using SecurityHealth.Api;
using Xunit;

namespace SecurityHealth.Api.Tests;

public sealed class SqlFactAttribute : FactAttribute
{
    public SqlFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("SECURITYHEALTH_TEST_SQL")))
            Skip = "Set SECURITYHEALTH_TEST_SQL to an isolated SQL Server test instance.";
    }
}

public sealed class SqlIntegrationTests
{
    [SqlFact]
    public async Task PersistsSnapshotsAtomicallyAndHandlesConcurrentReplay()
    {
        var adminString = Environment.GetEnvironmentVariable("SECURITYHEALTH_TEST_SQL")!;
        var database = "SecurityHealthTest_" + Guid.NewGuid().ToString("N");
        await using var admin = new SqlConnection(adminString);
        await admin.OpenAsync();
        await Execute(admin, $"CREATE DATABASE [{database}]");
        try
        {
            var settings = new SqlConnectionStringBuilder(adminString) { InitialCatalog = database };
            await using var connection = new SqlConnection(settings.ConnectionString);
            await connection.OpenAsync();
            await Execute(connection, await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "001-scans.sql")));
            var store = new SqlScanStore(() => new SqlConnection(settings.ConnectionString));
            var payload = IngestionTests.Payload(computer: "PC'; DROP TABLE dbo.Scans;--");
            using var json = JsonDocument.Parse(payload);
            Assert.True(ScanSubmission.TryCreate(json.RootElement, @"CORP\collector", out var submission));
            var scan = submission!;
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
            var results = await Task.WhenAll(Enumerable.Range(0, 5)
                .Select(_ => store.SaveAsync(scan, hash, CancellationToken.None)));
            Assert.Single(results, result => result == SaveResult.Created);
            Assert.Equal(4, results.Count(result => result == SaveResult.Duplicate));
            Assert.Equal(SaveResult.Conflict,
                await store.SaveAsync(scan, SHA256.HashData([1, 2, 3]), CancellationToken.None));
            Assert.Equal(SaveResult.Conflict,
                await store.SaveAsync(scan with { Uploader = @"CORP\another" }, hash, CancellationToken.None));

            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "SELECT SnapshotJson, Computer, ReceivedAtUtc FROM dbo.Scans";
                await using var reader = await command.ExecuteReaderAsync();
                Assert.True(await reader.ReadAsync());
                Assert.Equal(scan.SnapshotJson, reader.GetString(0));
                Assert.Equal(scan.Computer, reader.GetString(1));
                Assert.True(reader.GetDateTime(2) > DateTime.UtcNow.AddMinutes(-5));
                Assert.False(await reader.ReadAsync());
            }

            // A database constraint failure must not leave a partial row or lock.
            await Assert.ThrowsAsync<SqlException>(() =>
                store.SaveAsync(scan with { Id = Guid.NewGuid(), LookbackDays = 91 }, hash, CancellationToken.None));
            Assert.Equal(SaveResult.Created,
                await store.SaveAsync(scan with { Id = Guid.NewGuid() }, hash, CancellationToken.None));
            await Execute(connection, """
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID('dbo.Scans')
                               AND name = 'IX_Scans_Computer_Received')
                    THROW 50000, 'Missing host history index', 1;
                CREATE USER IngestionTest WITHOUT LOGIN;
                ALTER ROLE SecurityHealthIngest ADD MEMBER IngestionTest;
                EXECUTE AS USER = 'IngestionTest';
                IF HAS_PERMS_BY_NAME('dbo.Scans', 'OBJECT', 'INSERT') <> 1
                   OR HAS_PERMS_BY_NAME('dbo.Scans', 'OBJECT', 'SELECT') <> 1
                   OR HAS_PERMS_BY_NAME('dbo.Scans', 'OBJECT', 'DELETE') <> 0
                    THROW 50000, 'Incorrect ingestion role permissions', 1;
                REVERT;
                """);

            await Execute(connection, "DROP TABLE dbo.Scans");
            using var factory = new ApiFactory(persistence: store);
            using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
            client.DefaultRequestHeaders.Add("X-Test-User", @"CORP\collector");
            using var response = await client.PostAsync("/api/v1/scans",
                new StringContent(payload, Encoding.UTF8, "application/json"));
            Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
            var error = await response.Content.ReadAsStringAsync();
            Assert.Contains("correlationId", error);
            Assert.DoesNotContain("dbo.Scans", error);
            Assert.DoesNotContain(database, error);
            Assert.DoesNotContain(scan.Computer, error);
        }
        finally
        {
            SqlConnection.ClearAllPools();
            await Execute(admin, $"ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{database}]");
        }
    }

    private static async Task Execute(SqlConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
