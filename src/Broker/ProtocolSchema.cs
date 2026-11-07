using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Schema;

namespace Astra.Credentials;

public static class ProtocolSchema
{
  public static JsonNode Build()
  {
    var types = new[] { typeof(Greeting), typeof(Hello), typeof(Welcome), typeof(RpcResponse), typeof(ServiceStatus),
      typeof(CreateCredential), typeof(ListCredentials), typeof(Credential), typeof(CredentialPage), typeof(BeginUpdate),
      typeof(BeginResult), typeof(LeaseRef), typeof(CommitUpdate), typeof(AbortUpdate), typeof(Operation), typeof(EventPage),
      typeof(EventsRequest), typeof(WatchEventsRequest), typeof(IdRequest), typeof(OperationRequest), typeof(RegisterClient),
      typeof(RegisteredClient), typeof(ClientIdRequest), typeof(InitializeRequest), typeof(InitializeResult), typeof(TransferPackage),
      typeof(TransferSnapshot), typeof(VersionManifest), typeof(VaultManifest), typeof(ReadyRequest), typeof(HandoffRequest),
      typeof(ProofChallenge), typeof(UnlockRequest), typeof(ValidateMigration), typeof(MigrationValidation), typeof(PreparedResult), typeof(HandoffResult), typeof(SharingState),
      typeof(ComponentManifest), typeof(ComponentProbe), typeof(Installation), typeof(VaultRegistration), typeof(InstallJournal), typeof(InstallationStatus), typeof(RuntimeEndpoint) };
    var definitions = new JsonObject();
    foreach (var type in types)
    {
      var node = Protocol.Json.GetJsonSchemaAsNode(type, new JsonSchemaExporterOptions { TreatNullObliviousAsNonNullable = true });
      // A custom exact-decimal converter has no inferred schema. Preserve its numeric wire contract explicitly.
      if (node["properties"] is JsonObject properties && properties.ContainsKey("apiRevision"))
      {
        var api = new JsonObject
        {
          ["type"] = "number",
          ["minimum"] = 0,
          ["maximum"] = decimal.MaxValue,
          ["description"] = "Exact nonnegative decimal API level: 96-bit coefficient, scale 0..28; no floating-point rounding."
        };
        if (type == typeof(ComponentManifest) || type == typeof(ComponentProbe)) api["default"] = 0;
        properties["apiRevision"] = api;
      }
      // Export each type independently, then relocate local self-references into its definition.
      RewriteReferences(node, "#/$defs/" + type.Name);
      definitions[type.Name] = node;
    }
    definitions["Empty"] = new JsonObject { ["type"] = "object", ["additionalProperties"] = false };
    var methods = new (string Method, string Parameters)[] {
      ("status", "Empty"), ("getSharingState", "Empty"), ("heartbeat", "Empty"), ("disconnect", "Empty"),
      ("listCredentials", nameof(ListCredentials)), ("getCredential", nameof(IdRequest)),
      ("createCredential", nameof(CreateCredential)), ("beginUpdate", nameof(BeginUpdate)),
      ("markUpdateStarted", nameof(LeaseRef)), ("renewUpdate", nameof(LeaseRef)), ("commitUpdate", nameof(CommitUpdate)),
      ("abortUpdate", nameof(AbortUpdate)), ("getOperation", nameof(OperationRequest)), ("getEvents", nameof(EventsRequest)),
      ("cancelQueuedUpdate", nameof(OperationRequest)),
      ("watchEvents", nameof(WatchEventsRequest)), ("initialize", nameof(InitializeRequest)),
      ("recoverDelivery", "Empty"), ("acknowledgeDelivery", "Empty"), ("validateMigration", nameof(ValidateMigration)),
      ("prepareChallenge", "Empty"), ("prepareClient", nameof(ReadyRequest)), ("handoff", nameof(HandoffRequest)),
      ("registerClient", nameof(RegisterClient)), ("revokeClient", nameof(ClientIdRequest)), ("unlock", nameof(UnlockRequest)), ("stop", "Empty") };
    var requests = new JsonArray();
    foreach (var (method, parameters) in methods)
      requests.Add(new JsonObject
      {
        ["type"] = "object",
        ["additionalProperties"] = false,
        ["required"] = new JsonArray("protocolVersion", "id", "method", "params"),
        ["properties"] = new JsonObject
        {
          ["protocolVersion"] = new JsonObject { ["const"] = 1 },
          ["id"] = new JsonObject { ["type"] = "string", ["pattern"] = "^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$" },
          ["method"] = new JsonObject { ["const"] = method },
          ["params"] = new JsonObject { ["$ref"] = "#/$defs/" + parameters }
        }
      });
    return new JsonObject
    {
      ["$schema"] = "https://json-schema.org/draft/2020-12/schema",
      ["$id"] = "urn:astra:credential-broker:protocol:1",
      ["title"] = "Astra Credential Broker protocol v1 request",
      ["description"] = "Structural contract generated from strict C# DTOs. UTF-8 byte limits, authorization, crypto allowlists, revisions, leases and state transitions are additionally enforced by the broker; see docs/protocol.md.",
      ["$defs"] = definitions,
      ["oneOf"] = requests
    };
  }
  private static void RewriteReferences(JsonNode? node, string prefix)
  {
    if (node is JsonObject obj)
    {
      if (obj["$ref"] is JsonValue reference && reference.TryGetValue<string>(out var value) && value.StartsWith('#'))
        obj["$ref"] = prefix + value[1..];
      foreach (var pair in obj) RewriteReferences(pair.Value, prefix);
    }
    else if (node is JsonArray array) foreach (var child in array) RewriteReferences(child, prefix);
  }
}
