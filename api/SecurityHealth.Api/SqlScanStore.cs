using System.Data;
using System.Runtime.CompilerServices;
using Microsoft.Data.SqlClient;

[assembly: InternalsVisibleTo("SecurityHealth.Api.Tests")]

namespace SecurityHealth.Api;

public enum SaveResult { Created, Duplicate, Conflict }

public interface IScanStore
{
    Task<SaveResult> SaveAsync(ScanSubmission submission, byte[] hash, CancellationToken cancellationToken);
}

public sealed class SqlScanStore : IScanStore
{
    private readonly Func<SqlConnection> createConnection;

    public SqlScanStore(string connectionString)
    {
        var settings = new SqlConnectionStringBuilder(connectionString);
        if (!settings.IntegratedSecurity || settings.TrustServerCertificate ||
            !settings.Encrypt.Equals(SqlConnectionEncryptOption.Mandatory) &&
            !settings.Encrypt.Equals(SqlConnectionEncryptOption.Strict))
            throw new InvalidOperationException("SQL requires integrated security, encryption, and a trusted certificate.");
        settings.ConnectTimeout = 15;
        var validated = settings.ConnectionString;
        createConnection = () => new SqlConnection(validated);
    }

    internal SqlScanStore(Func<SqlConnection> createConnection) => this.createConnection = createConnection;

    public async Task<SaveResult> SaveAsync(ScanSubmission submission, byte[] hash, CancellationToken cancellationToken)
    {
        await using var connection = createConnection();
        await connection.OpenAsync(cancellationToken);
        await using var transaction = (SqlTransaction)await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken);
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandTimeout = 30;
        command.CommandText = """
            SELECT PayloadHash, Uploader FROM dbo.Scans WITH (UPDLOCK, HOLDLOCK) WHERE SubmissionId = @id;
            """;
        command.Parameters.Add("@id", SqlDbType.UniqueIdentifier).Value = submission.Id;
        await using (var reader = await command.ExecuteReaderAsync(cancellationToken))
        {
            if (await reader.ReadAsync(cancellationToken))
            {
                var identical = hash.AsSpan().SequenceEqual((byte[])reader["PayloadHash"]) &&
                    string.Equals((string)reader["Uploader"], submission.Uploader, StringComparison.OrdinalIgnoreCase);
                await reader.DisposeAsync();
                await transaction.CommitAsync(cancellationToken);
                return identical ? SaveResult.Duplicate : SaveResult.Conflict;
            }
        }
        command.CommandText = """
            INSERT dbo.Scans
                (SubmissionId, TransportVersion, SchemaVersion, ToolVersion, Computer, ScanTime,
                 CollectedBy, LookbackDays, Uploader, SubmittedAtUtc, PayloadHash, SnapshotJson)
            VALUES (@id, 1, 1, @version, @computer, @scanTime, @collectedBy, @days, @uploader,
                    @submitted, @hash, @json);
            """;
        command.Parameters.Add("@version", SqlDbType.NVarChar, 64).Value = submission.ToolVersion;
        command.Parameters.Add("@computer", SqlDbType.NVarChar, 255).Value = submission.Computer;
        command.Parameters.Add("@scanTime", SqlDbType.NVarChar, 128).Value = submission.ScanTime;
        command.Parameters.Add("@collectedBy", SqlDbType.NVarChar, 256).Value = submission.CollectedBy;
        command.Parameters.Add("@days", SqlDbType.Int).Value = submission.LookbackDays;
        command.Parameters.Add("@uploader", SqlDbType.NVarChar, 256).Value = submission.Uploader;
        command.Parameters.Add("@submitted", SqlDbType.DateTime2).Value = submission.SubmittedAt.UtcDateTime;
        command.Parameters.Add("@hash", SqlDbType.Binary, 32).Value = hash;
        command.Parameters.Add("@json", SqlDbType.NVarChar, -1).Value = submission.SnapshotJson;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return SaveResult.Created;
    }
}
