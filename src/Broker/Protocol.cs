using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Astra.Credentials;

public sealed class BrokerException(string code) : Exception(code)
{
  public string Code { get; } = code;
}

public static partial class Protocol
{
  public const int Version = 1;
  public const int MaxMessageBytes = 2 * 1024 * 1024;
  public const int MaxPayloadBytes = 1024 * 1024;
  public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
  {
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    PropertyNameCaseInsensitive = false,
    MaxDepth = 32,
    WriteIndented = false,
    RespectRequiredConstructorParameters = true,
    RespectNullableAnnotations = true,
    NumberHandling = JsonNumberHandling.Strict,
    TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver(),
    Converters = { new ApiLevelJsonConverter() },
  };

  [GeneratedRegex("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$", RegexOptions.CultureInvariant)]
  private static partial Regex IdPattern();

  public static string Id(string value)
  {
    Require(value is not null && IdPattern().IsMatch(value), "invalid-id");
    return value!;
  }

  public static long Revision(string value)
  {
    Require(value.Length is > 0 and <= 19 && value.All(char.IsAsciiDigit) &&
      (value.Length == 1 || value[0] != '0') &&
      long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out _), "invalid-revision");
    return long.Parse(value, CultureInfo.InvariantCulture);
  }

  public static string Decimal(long value) => value.ToString(CultureInfo.InvariantCulture);
  public static void Require(bool condition, string code)
  {
    if (!condition) throw new BrokerException(code);
  }

  public static JsonElement Parse(ReadOnlyMemory<byte> bytes)
  {
    Require(bytes.Length <= MaxMessageBytes, "message-too-large");
    using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
    CheckDuplicates(document.RootElement);
    return document.RootElement.Clone();
  }

  private static void CheckDuplicates(JsonElement element)
  {
    if (element.ValueKind == JsonValueKind.Object)
    {
      var names = new HashSet<string>(StringComparer.Ordinal);
      foreach (var property in element.EnumerateObject())
      {
        Require(names.Add(property.Name), "duplicate-property");
        CheckDuplicates(property.Value);
      }
    }
    else if (element.ValueKind == JsonValueKind.Array)
      foreach (var item in element.EnumerateArray()) CheckDuplicates(item);
  }

  public static T Decode<T>(JsonElement element) => element.Deserialize<T>(Json) ?? throw new BrokerException("invalid-request");
  public static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);

  public static Dictionary<string, string> Metadata(Dictionary<string, string>? value)
  {
    Require(value is not null && value.Count <= 64, "invalid-metadata");
    foreach (var (key, item) in value!)
    {
      Require(item is not null && Encoding.UTF8.GetByteCount(key) is > 0 and <= 128 &&
        Encoding.UTF8.GetByteCount(item) <= 1024, "invalid-metadata");
      ValidateUnicode(key);
      ValidateUnicode(item!);
    }
    Require(CanonicalJson.Bytes(JsonSerializer.SerializeToElement(value, Json)).Length <= 16 * 1024, "invalid-metadata");
    return new Dictionary<string, string>(value, StringComparer.Ordinal);
  }

  public static void ValidateUnicode(string value)
  {
    for (var i = 0; i < value.Length; i++)
      if (char.IsSurrogate(value[i]))
      {
        Require(char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]), "invalid-unicode");
        i++;
      }
  }
}

public sealed record RecordBody(string ContentType, int PayloadFormatVersion, string Payload, Dictionary<string, string> Metadata);
public sealed record CredentialDescription(string CredentialId, string Revision, string CreatedByClientId,
  string LastUpdatedByClientId, Dictionary<string, string> Metadata, string ContentType, int PayloadFormatVersion);
public sealed record Credential(CredentialDescription Description, string Payload);
public sealed record CreateCredential(string CredentialId, string OperationId, string ContentType,
  int PayloadFormatVersion, string Payload, Dictionary<string, string> Metadata, string? CoordinationKey = null);
public sealed record ListCredentials(int Limit = 50, string? AfterCredentialId = null,
  string? CreatedByClientId = null, string? LastUpdatedByClientId = null,
  Dictionary<string, string>? MetadataEquals = null);
public sealed record CredentialPage(CredentialDescription[] Items, string? NextCursor);
public sealed record BeginUpdate(string CredentialId, string ObservedRevision, string OperationId);
public sealed record LeaseRef(string OperationId, string LeaseId, string Fence, string Generation, string BaseRevision);
public sealed record CommitUpdate(LeaseRef Lease, string? Payload = null, string? ContentType = null,
  int? PayloadFormatVersion = null, Dictionary<string, string>? SetMetadata = null, string[]? RemoveKeys = null,
  bool Delete = false);
public sealed record AbortUpdate(LeaseRef Lease, string Result, string FailureCode, bool Retryable, string UpstreamOutcome);
public sealed record Operation(string OperationId, string CredentialId, string ClientId, string InstanceId,
  string Status, string? LeaseId, string Fence, string Generation, string BaseRevision,
  long GrantedAt, long ExpiresAt, long HardDeadline, string? ResultRevision = null,
  string? RequestHash = null, string? FailureCode = null, bool? Retryable = null, string? UpstreamOutcome = null);
public sealed record BeginResult(string Status, Credential? Credential, Operation? Operation);
public sealed record ChangeEvent(string CredentialId, string Revision, string EventSequence, string Kind);
public sealed record EventPage(ChangeEvent[] Items, string NextCursor);
public sealed record ClientGrant(string ClientId, string TokenHash, string[] Scopes, string[] CredentialIds, bool AllCredentials);
public sealed record Actor(string ClientId, string InstanceId, string[] Scopes, string[] CredentialIds, bool AllCredentials, bool IsAdmin = false)
{
  public void Demand(string scope, string? credentialId = null)
  {
    Protocol.Require(IsAdmin || Scopes.Contains(scope, StringComparer.Ordinal), "forbidden");
    if (credentialId is not null)
      Protocol.Require(IsAdmin || AllCredentials || CredentialIds.Contains(credentialId, StringComparer.Ordinal), "forbidden");
  }
  public bool CanSee(string id) => IsAdmin || AllCredentials || CredentialIds.Contains(id, StringComparer.Ordinal);
}
