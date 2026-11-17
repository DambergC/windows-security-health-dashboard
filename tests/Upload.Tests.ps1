#Requires -Modules Pester

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'TestHelpers.psm1') -Force
    Add-Type -AssemblyName System.Net.Http
    . ([scriptblock]::Create((Import-DashboardFunction `
        -FunctionName 'Assert-UploadConfiguration', 'Format-Value', 'Get-Section',
                      'ConvertTo-ScanSnapshot', 'New-ScanSnapshot', 'Save-ScanSnapshot',
                      'Invoke-ScanUploadRequest', 'Send-ScanSnapshot', 'Get-QuietExitCode',
                      'Invoke-QuietScan' `
        -VariableAssignment '$script:ToolVersion')))
    if (-not ('UploadHttpServer' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

public sealed class UploadHttpServer : IDisposable {
    private readonly TcpListener listener;
    private readonly Task worker;
    public string Endpoint { get; private set; }
    public string Received { get; private set; }

    public UploadHttpServer(string status, string body) {
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Endpoint = "http://127.0.0.1:" + ((IPEndPoint)listener.LocalEndpoint).Port + "/";
        worker = Task.Run(async delegate {
            using (var socket = await listener.AcceptTcpClientAsync())
            using (var stream = socket.GetStream()) {
                stream.ReadTimeout = 5000;
                var header = new StringBuilder();
                while (!header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) {
                    int next = stream.ReadByte();
                    if (next < 0 || header.Length > 16384) throw new InvalidOperationException("Invalid test request.");
                    header.Append((char)next);
                }
                int length = int.Parse(Regex.Match(header.ToString(), @"(?im)^Content-Length:\s*(\d+)").Groups[1].Value);
                var input = new byte[length];
                int offset = 0;
                while (offset < input.Length) {
                    int read = stream.Read(input, offset, input.Length - offset);
                    if (read == 0) throw new InvalidOperationException("Incomplete test request.");
                    offset += read;
                }
                Received = Encoding.UTF8.GetString(input);
                var output = Encoding.UTF8.GetBytes(body);
                var headers = Encoding.ASCII.GetBytes("HTTP/1.1 " + status +
                    "\r\nContent-Length: " + output.Length + "\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(headers, 0, headers.Length);
                await stream.WriteAsync(output, 0, output.Length);
            }
        });
    }

    public void Dispose() {
        listener.Stop();
        if (!worker.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Test HTTP server did not stop.");
        worker.GetAwaiter().GetResult();
    }
}
'@
    }
}

Describe 'Upload HTTP transport' {
    It 'sends exact UTF-8 bytes and reads a bounded acknowledgement' {
        # Only the internal transport uses loopback HTTP; public configuration requires HTTPS.
        $server = [UploadHttpServer]::new('201 Created', '{"status":"created"}')
        try {
            $body = '{"example":"caf' + [char]0xE9 + '"}'
            $response = Invoke-ScanUploadRequest $server.Endpoint ([System.Text.Encoding]::UTF8.GetBytes($body))
            $response.Status | Should -Be 201
            $response.Body | Should -Be '{"status":"created"}'
            $server.Received | Should -BeExactly $body
        }
        finally { $server.Dispose() }
    }

    It 'does not buffer error bodies and rejects oversized success bodies' {
        $server = [UploadHttpServer]::new('503 Service Unavailable', ('x' * 8192))
        try {
            $response = Invoke-ScanUploadRequest $server.Endpoint ([byte[]]@(123, 125))
            $response.Status | Should -Be 503
            $response.Body | Should -Be ''
        }
        finally { $server.Dispose() }
        $server = [UploadHttpServer]::new('201 Created', ('x' * 4097))
        try {
            { Invoke-ScanUploadRequest $server.Endpoint ([byte[]]@(123, 125)) } | Should -Throw '*response limit*'
        }
        finally { $server.Dispose() }
    }
}

Describe 'Upload configuration' {
    It 'requires explicit headless HTTPS without URL credentials or redirect hints' {
        { Assert-UploadConfiguration '' $false } | Should -Not -Throw
        { Assert-UploadConfiguration 'https://api.example/api/v1/scans' $true } | Should -Not -Throw
        { Assert-UploadConfiguration 'https://api.example/api/v1/scans' $false } | Should -Throw '*requires -Quiet*'
        foreach ($endpoint in @('http://api.example', '/api/v1/scans', 'https://user:pass@api.example',
                                 'https://api.example/#fragment', 'https://api.example/?key=value')) {
            { Assert-UploadConfiguration $endpoint $true } | Should -Throw '*HTTPS*'
        }
    }

    It 'exports the same wrapper used for uploads without schema drift' {
        $d = New-MockScan
        $path = Join-Path $TestDrive 'scan.json'
        [void](Save-ScanSnapshot $d $path)
        (Get-Content $path -Raw).Trim() | Should -Be ((New-ScanSnapshot $d | ConvertTo-Json -Depth 12).Trim())
    }
}

Describe 'Bounded snapshot upload' {
    BeforeEach {
        Mock Start-Sleep {}
        $script:Bodies = New-Object System.Collections.Generic.List[string]
    }

    It 'retries a transient HTTP failure with exactly the same ID and bytes' {
        Mock Invoke-ScanUploadRequest {
            $text = [System.Text.Encoding]::UTF8.GetString($Body)
            $script:Bodies.Add($text)
            if ($script:Bodies.Count -eq 1) {
                return [pscustomobject]@{ Status = 429; RetryAfter = 100000; Body = 'private server detail' }
            }
            $id = ($text | ConvertFrom-Json).SubmissionId
            [pscustomobject]@{ Status = 200; RetryAfter = 0; Body = ('{"submissionId":"' + $id + '","status":"duplicate"}') }
        }
        Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans'
        $script:Bodies.Count | Should -Be 2
        $script:Bodies[0] | Should -BeExactly $script:Bodies[1]
        ($script:Bodies[0] | ConvertFrom-Json).Snapshot.SchemaVersion | Should -Be 1
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 10 }
    }

    It 'stops after three attempts and never exposes response bodies' {
        Mock Invoke-ScanUploadRequest { [pscustomobject]@{ Status = 503; RetryAfter = 0; Body = 'SQL secret detail' } }
        { Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans' } | Should -Throw '*HTTP 503*'
        Should -Invoke Invoke-ScanUploadRequest -Times 3 -Exactly
        Should -Invoke Start-Sleep -Times 2 -Exactly
    }

    It 'does not retry permanent HTTP errors or redirects' {
        foreach ($code in @(301, 400, 401, 403, 409, 413, 415, 501)) {
            $script:HttpCode = $code
            Mock Invoke-ScanUploadRequest { [pscustomobject]@{ Status = $script:HttpCode; RetryAfter = 0; Body = '' } }
            { Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans' } | Should -Throw "*HTTP $code*"
        }
        Should -Invoke Invoke-ScanUploadRequest -Times 8 -Exactly
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }

    It 'rejects success without a matching durable acknowledgement' {
        Mock Invoke-ScanUploadRequest { [pscustomobject]@{ Status = 201; RetryAfter = 0; Body = '{"status":"created"}' } }
        { Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans' } | Should -Throw '*transport failed*'
        Should -Invoke Invoke-ScanUploadRequest -Times 1 -Exactly
    }

    It 'retries timeouts but not certificate validation failures' {
        Mock Invoke-ScanUploadRequest { throw [System.Threading.Tasks.TaskCanceledException]::new('timeout') }
        { Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans' } | Should -Throw
        Should -Invoke Invoke-ScanUploadRequest -Times 3 -Exactly
        Mock Invoke-ScanUploadRequest { throw [System.Security.Authentication.AuthenticationException]::new('certificate detail') }
        { Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans' } | Should -Throw
        Should -Invoke Invoke-ScanUploadRequest -Times 4 -Exactly
    }

    It 'retries an interrupted response stream' {
        Mock Invoke-ScanUploadRequest { throw [System.IO.IOException]::new('connection ended') }
        { Send-ScanSnapshot (New-MockScan) 'https://api.example/api/v1/scans' } | Should -Throw
        Should -Invoke Invoke-ScanUploadRequest -Times 3 -Exactly
    }

    It 'rejects oversized UTF-8 requests before opening a connection' {
        $d = New-MockScan
        $d.Large = ('x' * 16777216)
        Mock Invoke-ScanUploadRequest {}
        { Send-ScanSnapshot $d 'https://api.example/api/v1/scans' } | Should -Throw '*16 MiB*'
        Should -Invoke Invoke-ScanUploadRequest -Times 0 -Exactly
    }
}

Describe 'Headless upload integration' {
    BeforeAll {
        # A runspace worker replaces real Windows collection with a representative scan.
        $serialized = [System.Management.Automation.PSSerializer]::Serialize((New-MockScan)).Replace("'", "''")
        $script:RunspaceWorker = [scriptblock]::Create(@"
param(`$sync, `$target)
`$sync.Results[`$target] = [System.Management.Automation.PSSerializer]::Deserialize('$serialized')
"@)
        $script:ScanTimeoutSec = 30
        $script:MaxEventsPerLog = 10
        $script:SecurityCollector = {}
        function New-Findings { param($d) }
        function Get-HtmlReport { param($d) '<html>report</html>' }
    }

    BeforeEach {
        Mock Send-ScanSnapshot {}
    }

    It 'does not upload by default' {
        $rows = @(Invoke-QuietScan -Targets 'PC-042' -Days 7 -Throttle 1 -NoHtml)
        $rows[0].Status | Should -Be 'OK'
        $rows[0].UploadStatus | Should -Be 'DISABLED'
        Should -Invoke Send-ScanSnapshot -Times 0 -Exactly
    }

    It 'uploads without requiring file output' {
        $rows = @(Invoke-QuietScan -Targets 'PC-042' -Days 7 -Throttle 1 -NoHtml -Endpoint 'https://api.example/api/v1/scans')
        $rows[0].UploadStatus | Should -Be 'OK'
        $rows[0].JsonPath | Should -Be ''
        Should -Invoke Send-ScanSnapshot -Times 1 -Exactly
    }

    It 'keeps local snapshots and scan success when upload fails' {
        Mock Send-ScanSnapshot { throw 'sensitive server detail' }
        $rows = @(Invoke-QuietScan -Targets 'PC-042' -Days 7 -Throttle 1 -OutDir $TestDrive `
            -Endpoint 'https://api.example/api/v1/scans' -WarningAction SilentlyContinue)
        $rows[0].Status | Should -Be 'OK'
        $rows[0].UploadStatus | Should -Be 'FAILED'
        $rows[0].UploadError | Should -Not -Match 'sensitive'
        Test-Path $rows[0].JsonPath | Should -BeTrue
        Test-Path $rows[0].HtmlPath | Should -BeTrue
        Get-QuietExitCode $rows | Should -Be 4
    }

    It 'does not submit unsuccessful target scans' {
        $worker = $script:RunspaceWorker
        try {
            $script:RunspaceWorker = { param($sync, $target) $sync.Errors[$target] = 'scan failed' }
            $rows = @(Invoke-QuietScan -Targets 'PC-042' -Days 7 -Throttle 1 -NoHtml `
                -Endpoint 'https://api.example/api/v1/scans' -WarningAction SilentlyContinue)
            $rows[0].Status | Should -Be 'FAILED'
            $rows[0].UploadStatus | Should -Be 'NOT_SENT'
            Get-QuietExitCode $rows | Should -Be 3
            Should -Invoke Send-ScanSnapshot -Times 0 -Exactly
        }
        finally { $script:RunspaceWorker = $worker }
    }
}

Describe 'Quiet exit precedence' {
    It 'prioritizes scan failure, upload failure, regressions, and findings in that order' {
        $ok = [pscustomobject]@{ Status = 'OK'; UploadStatus = 'OK'; Critical = 0; Regressions = 0; Warning = 0 }
        Get-QuietExitCode @($ok) | Should -Be 0
        $ok.Warning = 1
        Get-QuietExitCode @($ok) | Should -Be 1
        $ok.Regressions = 1
        Get-QuietExitCode @($ok) | Should -Be 2
        $ok.UploadStatus = 'FAILED'
        Get-QuietExitCode @($ok) | Should -Be 4
        $failed = [pscustomobject]@{ Status = 'FAILED'; UploadStatus = 'NOT_SENT' }
        Get-QuietExitCode @($ok, $failed) | Should -Be 3
    }
}
