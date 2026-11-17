# Optional SQL ingestion API

The data path is **PowerShell collector -> HTTPS / Windows authentication ->
IIS / ASP.NET Core API -> SQL Server**. Clients never receive database credentials.
This server is separate from the single-file collector and is not included in
the PowerShell Gallery package. Offline scans and reports are unchanged.

## Requirements and deployment

- Windows Server with IIS, Windows Authentication, and the ASP.NET Core **10 LTS
  Hosting Bundle** installed after IIS (repair the bundle if IIS was added later).
- SQL Server 2016 or later. Use current supported and patched SQL Server/Windows
  releases. The server certificate must be valid for the SQL hostname and trusted
  by the API host.
- A domain service account or gMSA for the IIS application pool, with network
  access to SQL Server. Use a dedicated account, not the collector's scan account.
- A trusted HTTPS certificate for the IIS site; expose TCP 443 to authorized
  collectors only. Allow the API host, not clients, to reach SQL Server.

1. As a database administrator, create/select the intended database and run
   [`sql/001-scans.sql`](sql/001-scans.sql) once. It creates a table, host/time index,
   and ingestion role transactionally. It intentionally fails if already applied;
   API startup never changes the schema.
2. Provision the API service account in SQL and the database, substituting your
   real account and database:

   ```sql
   USE master;
   CREATE LOGIN [CORP\svc_security_api] FROM WINDOWS;
   USE SecurityHealth;
   CREATE USER [CORP\svc_security_api] FOR LOGIN [CORP\svc_security_api];
   ALTER ROLE SecurityHealthIngest ADD MEMBER [CORP\svc_security_api];
   ```

   This role grants only SELECT and INSERT on `dbo.Scans`. Do not grant the
   application schema-change, UPDATE, DELETE, or database-owner privileges.
3. Build on a machine with the .NET 10 SDK:

   ```sh
   dotnet publish api/SecurityHealth.Api -c Release -o publish/api
   ```

   Copy the published directory to a dedicated IIS site/application. Use an
   application pool with **No Managed Code**, the service identity above, and
   filesystem read/execute access. Do not grant write access to application files.
4. Configure these ASP.NET Core settings through deployment-managed configuration
   (environment-variable names shown; arrays use numbered suffixes):

   | Setting | Example |
   |---|---|
   | `ConnectionStrings__Scans` | `Server=sql.corp.example;Database=SecurityHealth;Integrated Security=true;Encrypt=true;TrustServerCertificate=false` |
   | `Ingestion__AllowedGroups__0` | `CORP\SecurityHealthCollectors` |
   | `Ingestion__AllowedUsers__0` | `CORP\svc_security_scan` |
   | `ASPNETCORE_ENVIRONMENT` | `Production` |

   Users **or** group membership authorize ingestion. Prefer a dedicated AD group.
   An authenticated principal with no matching configured identity/group receives
   403; missing/empty allowlists deny all uploads. The connection must use Windows
   integrated security, encryption, and certificate validation; insecure connection
   settings are rejected. No connection secrets belong in the repository.
5. In IIS, **disable Anonymous Authentication**, enable **Windows Authentication**,
   and require SSL for the application. Remove HTTP bindings or reject HTTP before
   authentication; do not rely on redirecting credential-bearing requests.
   Do not add a proxy that terminates TLS or injects identity headers: this design
   expects direct HTTPS access through IIS. If using a DNS alias, configure its
   HTTP SPN and IIS Windows authentication settings for your service identity;
   confirm Kerberos works under the actual scheduled-task account.
6. Recycle the pool, verify the checks below, and schedule collectors with
   `-Quiet -ApiEndpoint https://your-site/api/v1/scans`. Authorize the process
   account, not necessarily the account supplied to `-Credential` for target WinRM.

Database access uses the application identity, not impersonation of the uploader;
Kerberos delegation to SQL is not required. The API does not provide a query
endpoint or change the dashboard. Use a separately permissioned reporting identity
for SQL queries.

## Contract

`POST /api/v1/scans`, `Content-Type: application/json; charset=utf-8`, UTF-8 body,
maximum **16 MiB (16,777,216 bytes)**. IIS and the application enforce this limit.
IIS request filtering can reject oversized requests as 404.13 before application
code runs; the application returns 413. Neither truncates scans.

```json
{
  "TransportVersion": 1,
  "SubmissionId": "df5ad423-4f20-4b9d-a1b1-d5010ee79518",
  "SubmittedAtUtc": "2026-11-17T19:00:00Z",
  "Snapshot": {
    "SchemaVersion": 1,
    "ToolVersion": "1.5.0",
    "Computer": "PC-042",
    "ScanTime": "2026-11-17 19:00:00",
    "LookbackDays": "7",
    "CollectedBy": "CORP\\operator",
    "Sections": {
      "Meta": {
        "Kind": "props",
        "Props": { "ComputerName": "PC-042" }
      }
    }
  }
}
```

`Snapshot` is the same normalized schema-v1 wrapper used by JSON exports, including
all collected sections. Values inside `Props` and row objects are strings. Sections
have either `Kind: "props"` with an object `Props`, or `Kind: "rows"` with an array
`Rows` of string-valued objects. The API rejects malformed sections, duplicate
property names, unsupported versions, missing metadata, and invalid field lengths.
Limits: tool version 64 characters, computer 255, scan time 128, collector/uploader
256, section name 128, lookback 1-90, JSON depth 32. Required metadata is nonblank.

The collector creates a GUID and UTC submission time once per host upload and
reuses the **identical request bytes** on retries. SQL stores the snapshot JSON
unchanged, its metadata, uploader identity from Windows authentication, server
UTC receipt time, and SHA-256 hash of the request. Original display-oriented
`ScanTime` remains text: its timezone is not inferred. Query host history using
`ReceivedAtUtc`, which has a `(Computer, ReceivedAtUtc DESC)` index.

| Response | Meaning |
|---|---|
| 201 | New scan committed |
| 200 | Identical submission already committed by the same identity |
| 400 / 415 | Invalid contract / wrong content type |
| 401 / 403 | Not authenticated / not authorized |
| 409 | Submission ID reused with different bytes or uploader identity |
| 413 | Application body-size limit exceeded |
| 503 | SQL persistence failed; no success acknowledged |

Successful responses contain `submissionId`, `status` (`created` or `duplicate`),
and `correlationId`. Application error responses contain a sanitized `error` and
`correlationId`; IIS authentication/filtering errors may have IIS-native bodies.
The collector checks the acknowledgement before marking an upload successful.
Concurrent retries cannot create duplicate rows; success is returned only after
the database transaction commits.

The collector retries timeouts, connection interruptions, and HTTP
408/429/500/502/503/504 up to three attempts. Each attempt has a 30-second timeout;
backoff starts at 1 then 2 seconds, honoring Retry-After up to 10 seconds per delay.
TLS certificate errors, redirects, authorization failures, conflicts, and other
permanent errors are not retried. A process restart creates a new submission:
there is no persistent retry queue or replay command.

## Data handling

Snapshots contain sensitive host configuration, usernames, exclusions, and event
details. Restrict collector group membership, application and database access,
network reachability, and backups. Enable appropriate database/backup encryption
and define retention operationally; this version does not automatically delete data.
Collector-provided host/collector metadata is an assertion, not an authenticated
device identity. Audit `Uploader` separately, and do not grant clients reporting
access merely because they can ingest.

Do not enable request-body logging, ASP.NET detailed error pages, or HTTP tracing
that records authentication data in production. SQL failures log only the SQL error
number and correlation ID, not SQL exception messages or snapshots. The collector
emits a sanitized failure and keeps any requested reports; it never includes raw
server responses or credentials in its CSV or reports.

## Development and verification

```sh
dotnet test api/SecurityHealth.Api.Tests
dotnet publish api/SecurityHealth.Api -c Release
```

SQL integration tests skip unless `SECURITYHEALTH_TEST_SQL` is set. Point it only
at an **isolated disposable SQL Server** where the test administrator may create
and drop databases. Tests create a uniquely named `SecurityHealthTest_...` database
and remove that database in cleanup. CI starts a loopback-only SQL container with
an ephemeral password, runs all tests, and removes the container. SQL-login auth
and a self-signed SQL certificate are allowed only through an internal test seam;
production configuration does not permit these overrides.

API tests cover authorization, validation and exact request-size boundaries,
acknowledgements, SQL configuration, and actual persistence/concurrent replay.
Pester upload tests run with the existing `Invoke-Pester ./tests` command.

Before deploying, run this Windows/IIS smoke test; Linux tests substitute an
authenticated principal and cannot verify real AD/IIS integration:

1. Confirm anonymous access gets 401 and an authenticated non-allowlisted user
   gets 403, without inserting rows.
2. Under the scheduled-task identity, scan a real host with `-Quiet -OutputPath`
   and `-ApiEndpoint`. Confirm `UploadStatus = OK`, unchanged local JSON/HTML,
   and one SQL row with correct `Uploader`, metadata, and complete snapshot.
3. POST identical bytes twice under that identity: expect 201 then 200 and one
   row. Change the body with the same submission ID: expect 409.
4. Stop SQL in a nonproduction deployment, then repeat: expect upload failure
   after bounded retries, retained reports, and exit 4 (or 3 if a scan failed).
   Verify API logs contain a correlation ID but no request body or SQL details.
5. Confirm an untrusted HTTPS certificate fails without bypass/retry, HTTP is
   rejected by IIS, and SQL connects under the pool identity with certificate
   validation enabled. Confirm the pool identity cannot modify/delete scans.
