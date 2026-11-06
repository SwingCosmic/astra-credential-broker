using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Astra.Credentials;

public sealed class BrokerClock(TimeProvider? provider = null)
{
  private readonly TimeProvider time = provider ?? TimeProvider.System;
  private readonly long origin = (provider ?? TimeProvider.System).GetTimestamp();
  private long utcOrigin = (provider ?? TimeProvider.System).GetUtcNow().ToUnixTimeMilliseconds();
  private long watermark;
  public long Now
  {
    get
    {
      var elapsed = (long)time.GetElapsedTime(origin).TotalMilliseconds;
      var candidate = Math.Max(utcOrigin + elapsed, time.GetUtcNow().ToUnixTimeMilliseconds());
      watermark = Math.Max(watermark, candidate);
      return watermark;
    }
  }
  public void Observe(long value)
  {
    var now = Now;
    if (value > now) utcOrigin += value - now;
    watermark = Math.Max(watermark, value);
  }
}

internal sealed record StoredRecord(string Id, long Revision, string Created, string Updated, string Group, long Fence, string Sealed, bool Deleted);

public sealed class CredentialStore : IDisposable
{
  public const long LeaseTtl = 30_000;
  public const long MaxHoldTime = 120_000;
  public const long RenewInterval = 10_000;
  private readonly Database db;
  private readonly byte[] key;
  private readonly VersionManifest version;
  private readonly object gate = new();
  private readonly BrokerClock clock;
  private readonly string generation;
  public Action<string>? Fault { get; set; }

  public CredentialStore(Vault vault, VersionManifest version, byte[] key, string? generation = null, BrokerClock? clock = null, bool create = false)
  {
    this.version = version;
    this.key = key.ToArray();
    this.clock = clock ?? new();
    this.generation = generation ?? Crypto.RandomId();
    Vault.VerifyKey(version, key);
    db = new Database(Path.Combine(vault.VersionPath(version.StorageVersion), "credentials.db"), create, vault.Platform.Files);
    if (!create) Protocol.Require((long)db.Scalar("PRAGMA user_version")! == 1, "storage-incompatible");
    db.Execute("""
      CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY, revision INTEGER NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL,
        group_key TEXT NOT NULL, fence INTEGER NOT NULL DEFAULT 0, sealed TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS groups (group_key TEXT PRIMARY KEY, fence INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS operations (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
        group_key TEXT NOT NULL, begin_hash TEXT NOT NULL, state TEXT NOT NULL, json TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS operation_group_state ON operations(group_key,state,sequence);
      CREATE TABLE IF NOT EXISTS mutations (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, request_hash TEXT NOT NULL, revision TEXT NOT NULL, credential_id TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, credential_id TEXT NOT NULL, revision TEXT NOT NULL, kind TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK(id=1), watermark INTEGER NOT NULL);
      INSERT OR IGNORE INTO clock VALUES (1,0);
      PRAGMA user_version=1;
      """);
    this.clock.Observe((long)db.Scalar("SELECT watermark FROM clock WHERE id=1")!);
    // Crash recovery changes service generation but preserves absolute deadlines and fencing.
    Atomic(() =>
    {
      Expire();
      foreach (var op in Operations("state IN ('granted','started')")) Save(op with { Generation = this.generation });
      return true;
    });
  }

  private T Atomic<T>(Func<T> work)
  {
    lock (gate)
      return db.Atomic(() =>
      {
        var result = work();
        db.Execute("UPDATE clock SET watermark=$now WHERE id=1", ("$now", clock.Now));
        return result;
      });
  }

  private StoredRecord ReadStored(string id)
  {
    var records = db.Rows("SELECT id,revision,created,updated,group_key,fence,sealed,deleted FROM records WHERE id=$id",
      ReadStoredRow, ("$id", id));
    Protocol.Require(records.Count == 1, "credential-not-found");
    return records[0];
  }
  private static StoredRecord ReadStoredRow(Microsoft.Data.Sqlite.SqliteDataReader r) =>
    new(r.GetString(0), r.GetInt64(1), r.GetString(2), r.GetString(3), r.GetString(4), r.GetInt64(5), r.GetString(6), r.GetBoolean(7));
  private byte[] Aad(StoredRecord record) => CanonicalJson.Of(new
  {
    format = "astraconductor.credential-record",
    version = 1,
    version.VaultId,
    version.StorageVersion,
    version.AttemptId,
    version.KeyId,
    credentialId = record.Id,
    revision = Protocol.Decimal(record.Revision),
    createdByClientId = record.Created,
    lastUpdatedByClientId = record.Updated,
    coordinationKey = record.Group,
    deleted = record.Deleted,
  });
  private Credential Decode(StoredRecord record)
  {
    Protocol.Require(!record.Deleted, "credential-deleted");
    var sealedBytes = Protocol.Decode<SealedBytes>(Protocol.Parse(Encoding.UTF8.GetBytes(record.Sealed)));
    var plain = Crypto.Decrypt(key, sealedBytes, Aad(record));
    try
    {
      var body = Protocol.Decode<RecordBody>(Protocol.Parse(plain));
      return new(new(record.Id, Protocol.Decimal(record.Revision), record.Created, record.Updated,
        body.Metadata, body.ContentType, body.PayloadFormatVersion), body.Payload);
    }
    finally { CryptographicOperations.ZeroMemory(plain); }
  }
  private StoredRecord Encrypt(StoredRecord record, RecordBody body)
  {
    var plain = CanonicalJson.Of(body);
    try { return record with { Sealed = JsonSerializer.Serialize(Crypto.Encrypt(key, plain, Aad(record)), Protocol.Json) }; }
    finally { CryptographicOperations.ZeroMemory(plain); }
  }
  private static void ValidateBody(RecordBody body)
  {
    Protocol.Require(body.ContentType.Length is > 0 and <= 256 && body.PayloadFormatVersion is > 0 and <= 1000, "invalid-payload-format");
    _ = Crypto.Unb64(body.Payload, Protocol.MaxPayloadBytes);
    Protocol.Metadata(body.Metadata);
  }
  private void WriteRecord(StoredRecord record) => db.Execute("""
    INSERT INTO records VALUES ($id,$revision,$created,$updated,$group,$fence,$sealed,$deleted)
    ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,updated=excluded.updated,
      fence=excluded.fence,sealed=excluded.sealed,deleted=excluded.deleted
    """, ("$id", record.Id), ("$revision", record.Revision), ("$created", record.Created), ("$updated", record.Updated),
    ("$group", record.Group), ("$fence", record.Fence), ("$sealed", record.Sealed), ("$deleted", record.Deleted));
  private void Emit(string id, long revision, string kind) => db.Execute(
    "INSERT INTO events (credential_id,revision,kind) VALUES ($id,$rev,$kind)", ("$id", id), ("$rev", Protocol.Decimal(revision)), ("$kind", kind));

  public Credential InsertInitial(Actor actor, InitialRecord request) => Atomic(() =>
    Insert(actor, request));

  private Credential Insert(Actor actor, InitialRecord request)
  {
    Protocol.Id(request.CredentialId);
    var body = new RecordBody(request.ContentType, request.PayloadFormatVersion, request.Payload, Protocol.Metadata(request.Metadata));
    ValidateBody(body);
    Protocol.Require(db.Scalar("SELECT id FROM records WHERE id=$id", ("$id", request.CredentialId)) is null, "credential-exists");
    var group = request.CoordinationKey is null ? "record:" + request.CredentialId : "family:" + Protocol.Id(request.CoordinationKey);
    var stored = Encrypt(new(request.CredentialId, 1, actor.ClientId, actor.ClientId, group, 0, "", false), body);
    WriteRecord(stored);
    db.Execute("INSERT OR IGNORE INTO groups VALUES ($key,0)", ("$key", group));
    Emit(stored.Id, 1, "credentialChanged");
    return Decode(stored);
  }

  public Credential Create(Actor actor, CreateCredential request) => Atomic(() =>
  {
    actor.Demand("create", request.CredentialId);
    actor.Demand("read", request.CredentialId);
    Protocol.Id(request.OperationId);
    Protocol.Require(FindOperation(request.OperationId) is null, "operation-conflict");
    var existing = db.Rows("SELECT client_id,request_hash,credential_id FROM mutations WHERE id=$id",
      r => (r.GetString(0), r.GetString(1), r.GetString(2)), ("$id", request.OperationId));
    var hash = Crypto.HashObject(request);
    if (existing.Count > 0)
    {
      Protocol.Require(existing[0].Item1 == actor.ClientId && existing[0].Item2 == hash, "operation-conflict");
      return Decode(ReadStored(existing[0].Item3));
    }
    var result = Insert(actor, new(request.CredentialId, request.ContentType, request.PayloadFormatVersion,
      request.Payload, request.Metadata, request.CoordinationKey));
    db.Execute("INSERT INTO mutations VALUES ($id,$client,$hash,'1',$credential)", ("$id", request.OperationId),
      ("$client", actor.ClientId), ("$hash", hash), ("$credential", request.CredentialId));
    Fault?.Invoke("create-before-commit");
    return result;
  });

  public Credential Get(Actor actor, string id)
  {
    lock (gate) { actor.Demand("read", id); return Decode(ReadStored(Protocol.Id(id))); }
  }

  public CredentialPage List(Actor actor, ListCredentials request)
  {
    lock (gate)
    {
      actor.Demand("describe");
      Protocol.Require(request.Limit is >= 1 and <= 200, "invalid-page-size");
      if (request.AfterCredentialId is not null) Protocol.Id(request.AfterCredentialId);
      var filter = Protocol.Metadata(request.MetadataEquals ?? []);
      var rows = db.Rows("SELECT id,revision,created,updated,group_key,fence,sealed,deleted FROM records WHERE deleted=0 AND id>$after ORDER BY id COLLATE BINARY",
        ReadStoredRow, ("$after", request.AfterCredentialId ?? ""));
      var descriptions = new List<CredentialDescription>();
      var wireBytes = 256;
      var more = false;
      foreach (var row in rows)
      {
        if (!actor.CanSee(row.Id) || (request.CreatedByClientId is not null && row.Created != request.CreatedByClientId) ||
          (request.LastUpdatedByClientId is not null && row.Updated != request.LastUpdatedByClientId)) continue;
        var description = Decode(row).Description;
        if (!filter.All(pair => description.Metadata.TryGetValue(pair.Key, out var value) && value == pair.Value)) continue;
        var size = Protocol.Encode(description).Length + 1;
        if (descriptions.Count >= request.Limit || wireBytes + size > Protocol.MaxMessageBytes - 4096)
        {
          more = true;
          break;
        }
        descriptions.Add(description);
        wireBytes += size;
      }
      return new(descriptions.ToArray(), more ? descriptions[^1].CredentialId : null);
    }
  }

  private List<Operation> Operations(string where, params (string Name, object? Value)[] args) => db.Rows(
    "SELECT json FROM operations WHERE " + where + " ORDER BY sequence", r => Protocol.Decode<Operation>(Protocol.Parse(Encoding.UTF8.GetBytes(r.GetString(0)))), args);
  private Operation? FindOperation(string id) => Operations("id=$id", ("$id", id)).FirstOrDefault();
  private void Save(Operation op) => db.Execute("UPDATE operations SET state=$state,json=$json WHERE id=$id",
    ("$state", op.Status), ("$json", JsonSerializer.Serialize(op, Protocol.Json)), ("$id", op.OperationId));
  private long BumpFence(string group)
  {
    db.Execute("UPDATE groups SET fence=fence+1 WHERE group_key=$key", ("$key", group));
    return (long)db.Scalar("SELECT fence FROM groups WHERE group_key=$key", ("$key", group))!;
  }
  private void Expire()
  {
    var now = clock.Now;
    foreach (var queued in Operations("state='queued'"))
      if (now >= queued.HardDeadline) Save(queued with { Status = "cancelled" });
    foreach (var op in Operations("state IN ('granted','started')"))
      if (now >= op.ExpiresAt || now >= op.HardDeadline)
      {
        Save(op with { Status = "expired", UpstreamOutcome = op.Status == "started" ? "unknown" : "unchanged" });
        BumpFence(ReadStored(op.CredentialId).Group);
      }
  }

  public BeginResult Begin(Actor actor, BeginUpdate request) => Atomic<BeginResult>(() =>
  {
    actor.Demand("update", request.CredentialId);
    actor.Demand("read", request.CredentialId);
    Protocol.Id(request.OperationId);
    Protocol.Revision(request.ObservedRevision);
    Expire();
    Protocol.Require(db.Scalar("SELECT id FROM mutations WHERE id=$id", ("$id", request.OperationId)) is null, "operation-conflict");
    var row = ReadStored(request.CredentialId);
    var credential = Decode(row);
    var op = FindOperation(request.OperationId);
    var hash = Crypto.HashObject(request);
    if (op is not null)
    {
      var original = db.Scalar("SELECT begin_hash FROM operations WHERE id=$id", ("$id", request.OperationId)) as string;
      Protocol.Require(op.ClientId == actor.ClientId && op.InstanceId == actor.InstanceId && original == hash, "operation-conflict");
      if (op.Status != "queued") return new(op.Status, op.Status is "granted" or "started" or "stale" ? credential : null, op);
    }
    else
    {
      var status = request.ObservedRevision == credential.Description.Revision ? "queued" : "stale";
      op = new(request.OperationId, request.CredentialId, actor.ClientId, actor.InstanceId, status,
        null, "0", generation, request.ObservedRevision, clock.Now, 0, clock.Now + MaxHoldTime);
      db.Execute("INSERT INTO operations (id,group_key,begin_hash,state,json) VALUES ($id,$group,$hash,$state,$json)",
        ("$id", op.OperationId), ("$group", row.Group), ("$hash", hash), ("$state", status), ("$json", JsonSerializer.Serialize(op, Protocol.Json)));
      if (status == "stale") return new("stale", credential, op);
    }
    // A queued caller cannot overtake an earlier caller. Poll beginUpdate using the same operationId.
    var first = Operations("group_key=$group AND state='queued'", ("$group", row.Group)).First();
    var active = Operations("group_key=$group AND state IN ('granted','started')", ("$group", row.Group));
    if (first.OperationId != op.OperationId || active.Count != 0) return new("queued", null, op);
    if (request.ObservedRevision != credential.Description.Revision)
    {
      op = op with { Status = "stale", ResultRevision = credential.Description.Revision };
      Save(op);
      return new("stale", credential, op);
    }
    var now = clock.Now;
    op = op with
    {
      Status = "granted",
      LeaseId = Crypto.RandomId(),
      Fence = Protocol.Decimal(BumpFence(row.Group)),
      Generation = generation,
      GrantedAt = now,
      ExpiresAt = now + LeaseTtl,
      HardDeadline = now + MaxHoldTime
    };
    Save(op);
    return new("granted", credential, op);
  });

  private Operation Owned(Actor actor, string id)
  {
    var op = FindOperation(Protocol.Id(id)) ?? throw new BrokerException("operation-not-found");
    Protocol.Require(op.ClientId == actor.ClientId && op.InstanceId == actor.InstanceId, "forbidden");
    actor.Demand("update", op.CredentialId);
    return op;
  }
  private Operation ValidLease(Actor actor, LeaseRef lease)
  {
    var op = Owned(actor, lease.OperationId);
    Protocol.Require(op.Status is "granted" or "started", op.Status == "expired" ? "lease-expired" : "operation-terminal");
    Protocol.Require(op.LeaseId == lease.LeaseId && op.Fence == lease.Fence && op.Generation == lease.Generation &&
      op.BaseRevision == lease.BaseRevision && op.Generation == generation, "stale-fence");
    Protocol.Require(clock.Now < op.ExpiresAt && clock.Now < op.HardDeadline, "lease-expired");
    return op;
  }

  public Operation MarkStarted(Actor actor, LeaseRef lease) => Atomic(() =>
  {
    Expire();
    var op = ValidLease(actor, lease) with { Status = "started" };
    Save(op);
    Fault?.Invoke("started-before-commit");
    return op;
  });
  public Operation Renew(Actor actor, LeaseRef lease) => Atomic(() =>
  {
    Expire();
    var op = ValidLease(actor, lease);
    op = op with { ExpiresAt = Math.Min(clock.Now + LeaseTtl, op.HardDeadline) };
    Save(op);
    return op;
  });
  public Operation Commit(Actor actor, CommitUpdate request) => Atomic(() =>
  {
    Expire();
    var hash = Crypto.HashObject(request);
    var previous = Owned(actor, request.Lease.OperationId);
    if (previous.Status == "committed")
    {
      Protocol.Require(previous.RequestHash == hash, "operation-conflict");
      return previous;
    }
    var op = ValidLease(actor, request.Lease);
    var row = ReadStored(op.CredentialId);
    Protocol.Require(Protocol.Decimal(row.Revision) == op.BaseRevision, "revision-conflict");
    Protocol.Require(op.Status == "started", "update-not-started");
    var current = Decode(row);
    var metadata = Protocol.Metadata(current.Description.Metadata);
    if (request.SetMetadata is not null)
      foreach (var (name, value) in Protocol.Metadata(request.SetMetadata)) metadata[name] = value;
    if (request.RemoveKeys is not null)
    {
      Protocol.Require(request.RemoveKeys.Length <= 64 && request.RemoveKeys.Distinct(StringComparer.Ordinal).Count() == request.RemoveKeys.Length, "invalid-remove-keys");
      foreach (var name in request.RemoveKeys)
      {
        Protocol.Metadata(new() { [name] = "" });
        metadata.Remove(name);
      }
    }
    var body = new RecordBody(request.ContentType ?? current.Description.ContentType,
      request.PayloadFormatVersion ?? current.Description.PayloadFormatVersion,
      request.Payload ?? current.Payload, Protocol.Metadata(metadata));
    ValidateBody(body);
    if (request.Delete)
    {
      actor.Demand("delete", row.Id);
      Protocol.Require(request.Payload is null && request.SetMetadata is null && request.RemoveKeys is null, "invalid-delete");
    }
    row = row with
    {
      Revision = checked(row.Revision + 1),
      Updated = actor.ClientId,
      Fence = Protocol.Revision(op.Fence),
      Deleted = request.Delete
    };
    row = Encrypt(row, request.Delete ? new("application/octet-stream", 1, "", []) : body);
    WriteRecord(row);
    Fault?.Invoke("record-written");
    Emit(row.Id, row.Revision, request.Delete ? "credentialDeleted" : "credentialChanged");
    op = op with { Status = "committed", ResultRevision = Protocol.Decimal(row.Revision), RequestHash = hash };
    Save(op);
    Fault?.Invoke("commit-before-transaction");
    return op;
  });

  public Operation Abort(Actor actor, AbortUpdate request) => Atomic(() =>
  {
    Protocol.Require(request.Result == "failed" && request.UpstreamOutcome is "unchanged" or "unknown", "invalid-abort");
    Protocol.Require(new[] { "network-error", "request-timeout", "provider-error", "parse-error", "cancelled",
      "upstream-unknown", "authorization-required", "invalid-result", "client-shutdown", "unknown-error" }
      .Contains(request.FailureCode, StringComparer.Ordinal), "invalid-failure-code");
    Expire();
    var old = Owned(actor, request.Lease.OperationId);
    var hash = Crypto.HashObject(request);
    if (old.Status == "committed" || old.Status is "expired" or "cancelled" or "stale") return old;
    if (old.Status == "failed-released")
    {
      Protocol.Require(old.RequestHash == hash, "operation-conflict");
      return old;
    }
    var op = ValidLease(actor, request.Lease) with
    {
      Status = "failed-released",
      RequestHash = hash,
      FailureCode = request.FailureCode,
      Retryable = request.Retryable,
      UpstreamOutcome = request.UpstreamOutcome,
    };
    Save(op);
    return op;
  });

  public Operation GetOperation(Actor actor, string id) => Atomic(() => { Expire(); return Owned(actor, id); });

  public void Disconnect(Actor actor)
  {
    lock (gate)
    {
      // In-flight leases survive transient disconnect. A status-only management connection
      // has no queue tickets, so disconnecting it must not start a write transaction.
      var queued = Operations("state='queued'").Where(op => op.ClientId == actor.ClientId && op.InstanceId == actor.InstanceId).ToArray();
      if (queued.Length == 0) return;
      Atomic(() =>
      {
        foreach (var op in queued) Save(op with { Status = "cancelled" });
        return true;
      });
    }
  }

  public EventPage Events(Actor actor, string cursor, int limit = 100)
  {
    lock (gate)
    {
      actor.Demand("events");
      Protocol.Require(limit is >= 1 and <= 200, "invalid-page-size");
      var start = Protocol.Revision(cursor);
      var events = db.Rows("SELECT credential_id,revision,sequence,kind FROM events WHERE sequence>$cursor ORDER BY sequence LIMIT 1000",
        r => new ChangeEvent(r.GetString(0), r.GetString(1), Protocol.Decimal(r.GetInt64(2)), r.GetString(3)), ("$cursor", start));
      var result = new List<ChangeEvent>();
      var next = cursor;
      foreach (var item in events)
      {
        next = item.EventSequence;
        if (actor.CanSee(item.CredentialId)) result.Add(item);
        if (result.Count == limit) break;
      }
      return new(result.ToArray(), next);
    }
  }

  public bool HasPending
  {
    get
    {
      lock (gate)
      {
        // The 200 ms idle poll must remain read-only when there are no leases or queue
        // tickets. Active operations retain expiry, fencing and durable clock handling.
        if ((long)db.Scalar("SELECT EXISTS(SELECT 1 FROM operations WHERE state IN ('queued','granted','started'))")! == 0)
          return false;
        return Atomic(() => { Expire(); return Operations("state IN ('granted','started')").Count > 0; });
      }
    }
  }
  public void Dispose() { db.Dispose(); CryptographicOperations.ZeroMemory(key); }
}
