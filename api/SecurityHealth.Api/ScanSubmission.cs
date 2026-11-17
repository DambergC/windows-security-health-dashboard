using System.Globalization;
using System.Text.Json;

namespace SecurityHealth.Api;

public sealed record ScanSubmission(
    Guid Id, DateTimeOffset SubmittedAt, string ToolVersion, string Computer,
    string ScanTime, string CollectedBy, int LookbackDays, string Uploader, string SnapshotJson)
{
    public const int MaxBytes = 16 * 1024 * 1024;

    public static bool TryCreate(JsonElement root, string? uploader, out ScanSubmission? submission)
    {
        submission = null;
        if (root.ValueKind != JsonValueKind.Object || !UniqueProperties(root) ||
            !Integer(root, "TransportVersion", out var transport) || transport != 1 ||
            !Text(root, "SubmissionId", 36, out var idText) ||
            !Guid.TryParseExact(idText, "D", out var id) || id == Guid.Empty ||
            !Text(root, "SubmittedAtUtc", 40, out var timeText) ||
            !DateTimeOffset.TryParse(timeText, CultureInfo.InvariantCulture,
                DateTimeStyles.None, out var time) || time.Offset != TimeSpan.Zero ||
            !(timeText.EndsWith('Z') || timeText.EndsWith("+00:00", StringComparison.Ordinal)) ||
            !root.TryGetProperty("Snapshot", out var snapshot) || snapshot.ValueKind != JsonValueKind.Object ||
            !Integer(snapshot, "SchemaVersion", out var schema) || schema != 1 ||
            !Text(snapshot, "ToolVersion", 64, out var version) ||
            !Text(snapshot, "Computer", 255, out var computer) ||
            !Text(snapshot, "ScanTime", 128, out var scanTime) ||
            !Text(snapshot, "CollectedBy", 256, out var collectedBy) ||
            !Text(snapshot, "LookbackDays", 3, out var daysText) ||
            !int.TryParse(daysText, NumberStyles.None, CultureInfo.InvariantCulture, out var days) ||
            days is < 1 or > 90 || string.IsNullOrWhiteSpace(uploader) || uploader.Length > 256 ||
            !snapshot.TryGetProperty("Sections", out var sections) ||
            sections.ValueKind != JsonValueKind.Object || !sections.EnumerateObject().Any())
            return false;

        foreach (var section in sections.EnumerateObject())
        {
            if (string.IsNullOrWhiteSpace(section.Name) || section.Name.Length > 128 ||
                section.Value.ValueKind != JsonValueKind.Object ||
                !Text(section.Value, "Kind", 5, out var kind))
                return false;
            if (kind == "props")
            {
                if (!section.Value.TryGetProperty("Props", out var props) || !StringProperties(props))
                    return false;
            }
            else if (kind == "rows")
            {
                if (!section.Value.TryGetProperty("Rows", out var rows) || rows.ValueKind != JsonValueKind.Array ||
                    rows.EnumerateArray().Any(row => !StringProperties(row)))
                    return false;
            }
            else return false;
        }
        submission = new(id, time, version, computer, scanTime, collectedBy, days, uploader, snapshot.GetRawText());
        return true;
    }

    private static bool UniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || !UniqueProperties(property.Value)) return false;
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray())
                if (!UniqueProperties(item)) return false;
        return true;
    }

    private static bool StringProperties(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object &&
        element.EnumerateObject().All(property => property.Value.ValueKind == JsonValueKind.String);

    private static bool Integer(JsonElement element, string name, out int value)
    {
        value = 0;
        return element.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Number &&
               property.TryGetInt32(out value);
    }

    private static bool Text(JsonElement element, string name, int maxLength, out string value)
    {
        value = "";
        if (!element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String)
            return false;
        value = property.GetString()!;
        return !string.IsNullOrWhiteSpace(value) && value.Length <= maxLength &&
               !value.Any(char.IsControl);
    }
}
