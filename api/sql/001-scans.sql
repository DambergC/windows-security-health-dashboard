-- Run explicitly in the intended database as a deployment administrator.
SET XACT_ABORT ON;
BEGIN TRANSACTION;

CREATE TABLE dbo.Scans (
    SubmissionId uniqueidentifier NOT NULL CONSTRAINT PK_Scans PRIMARY KEY,
    TransportVersion int NOT NULL CONSTRAINT CK_Scans_Transport CHECK (TransportVersion = 1),
    SchemaVersion int NOT NULL CONSTRAINT CK_Scans_Schema CHECK (SchemaVersion = 1),
    ToolVersion nvarchar(64) NOT NULL,
    Computer nvarchar(255) NOT NULL,
    ScanTime nvarchar(128) NOT NULL,
    CollectedBy nvarchar(256) NOT NULL,
    LookbackDays int NOT NULL CONSTRAINT CK_Scans_Lookback CHECK (LookbackDays BETWEEN 1 AND 90),
    Uploader nvarchar(256) NOT NULL,
    SubmittedAtUtc datetime2(7) NOT NULL,
    ReceivedAtUtc datetime2(7) NOT NULL CONSTRAINT DF_Scans_Received DEFAULT SYSUTCDATETIME(),
    PayloadHash binary(32) NOT NULL,
    SnapshotJson nvarchar(max) NOT NULL CONSTRAINT CK_Scans_Json CHECK (ISJSON(SnapshotJson) = 1)
);
CREATE INDEX IX_Scans_Computer_Received ON dbo.Scans (Computer, ReceivedAtUtc DESC);
CREATE ROLE SecurityHealthIngest;
GRANT SELECT, INSERT ON dbo.Scans TO SecurityHealthIngest;

COMMIT TRANSACTION;
