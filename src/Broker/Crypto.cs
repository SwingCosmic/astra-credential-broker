using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Astra.Credentials;

// This protocol uses only strings, booleans and safe integers in canonicalized objects.
// Arbitrary JSON numbers are intentionally outside its canonicalization domain.
public static class CanonicalJson
{
  public static byte[] Bytes(JsonElement value)
  {
    var builder = new StringBuilder();
    Write(builder, value);
    return new UTF8Encoding(false, true).GetBytes(builder.ToString());
  }
  public static byte[] Of<T>(T value) => Bytes(JsonSerializer.SerializeToElement(value, Protocol.Json));
  private static void String(StringBuilder writer, string value)
  {
    Protocol.ValidateUnicode(value);
    writer.Append('"');
    foreach (var c in value)
      switch (c)
      {
        case '"': writer.Append("\\\""); break;
        case '\\': writer.Append("\\\\"); break;
        case '\b': writer.Append("\\b"); break;
        case '\t': writer.Append("\\t"); break;
        case '\n': writer.Append("\\n"); break;
        case '\f': writer.Append("\\f"); break;
        case '\r': writer.Append("\\r"); break;
        default:
          if (c < 0x20) writer.Append("\\u" + ((int)c).ToString("x4", System.Globalization.CultureInfo.InvariantCulture));
          else writer.Append(c);
          break;
      }
    writer.Append('"');
  }
  private static void Write(StringBuilder writer, JsonElement value)
  {
    switch (value.ValueKind)
    {
      case JsonValueKind.Object:
        writer.Append('{');
        var first = true;
        foreach (var property in value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
        {
          if (!first) writer.Append(',');
          first = false;
          String(writer, property.Name);
          writer.Append(':');
          Write(writer, property.Value);
        }
        writer.Append('}');
        break;
      case JsonValueKind.Array:
        writer.Append('[');
        var index = 0;
        foreach (var item in value.EnumerateArray()) { if (index++ > 0) writer.Append(','); Write(writer, item); }
        writer.Append(']');
        break;
      case JsonValueKind.String:
        String(writer, value.GetString()!);
        break;
      case JsonValueKind.Number:
        Protocol.Require(value.TryGetInt64(out var integer) && Math.Abs((decimal)integer) <= 9007199254740991, "noncanonical-number");
        writer.Append(Protocol.Decimal(integer));
        break;
      case JsonValueKind.True: writer.Append("true"); break;
      case JsonValueKind.False: writer.Append("false"); break;
      case JsonValueKind.Null: writer.Append("null"); break;
      default: throw new BrokerException("invalid-json");
    }
  }
}

public sealed record SealedBytes(string Nonce, string Ciphertext, string Tag);
public sealed record CipherHeader(string Name, string Nonce, int TagLength);
public sealed record KdfHeader(string Name, string Salt, string Info, int OutputLength);
public sealed record TransferHeader(string Format, int Version, string VaultId, string StorageVersion,
  string AttemptId, string TransferId, string KeyId, CipherHeader Cipher, KdfHeader Kdf, int PayloadSchemaVersion);
public sealed record TransferPackage(TransferHeader Header, string Ciphertext, string Tag);
public sealed record TransferSnapshot(string VaultId, string StorageVersion, string AttemptId, string KeyId,
  string MasterKey, Credential[] Records);

public static class Crypto
{
  public static string B64(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
  public static byte[] Unb64(string value, int max = Protocol.MaxMessageBytes)
  {
    Protocol.Require(value is not null && value.Length <= (max * 4L + 2) / 3 &&
      value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') && value.Length % 4 != 1, "invalid-base64url");
    var result = Convert.FromBase64String(value!.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    Protocol.Require(result.Length <= max && B64(result) == value, "invalid-base64url");
    return result;
  }
  public static string RandomId() => Guid.NewGuid().ToString("N");
  public static string Hash(byte[] bytes) => B64(SHA256.HashData(bytes));
  public static string HashObject<T>(T value) => Hash(CanonicalJson.Of(value));
  public static bool Equal(string a, string b) => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
  public static SealedBytes Encrypt(byte[] key, byte[] plain, byte[] aad)
  {
    var nonce = RandomNumberGenerator.GetBytes(12);
    var cipher = new byte[plain.Length];
    var tag = new byte[16];
    using var aes = new AesGcm(key, 16);
    aes.Encrypt(nonce, plain, cipher, tag, aad);
    return new(B64(nonce), B64(cipher), B64(tag));
  }
  public static byte[] Decrypt(byte[] key, SealedBytes value, byte[] aad)
  {
    var nonce = Unb64(value.Nonce, 12);
    var tag = Unb64(value.Tag, 16);
    Protocol.Require(nonce.Length == 12 && tag.Length == 16 && key.Length == 32, "invalid-crypto-parameters");
    var cipher = Unb64(value.Ciphertext);
    var plain = new byte[cipher.Length];
    using var aes = new AesGcm(key, 16);
    aes.Decrypt(nonce, cipher, tag, plain, aad);
    return plain;
  }
  public static (TransferPackage Package, string MigrationKey) Pack(TransferSnapshot snapshot)
  {
    var migration = RandomNumberGenerator.GetBytes(32);
    var salt = RandomNumberGenerator.GetBytes(32);
    var transferId = RandomId();
    var info = CanonicalJson.Of(new[] { "astraconductor.credential-transfer.v1", snapshot.VaultId,
      snapshot.StorageVersion, snapshot.AttemptId, transferId });
    var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, migration, 32, salt, info);
    try
    {
      var nonce = RandomNumberGenerator.GetBytes(12);
      var header = new TransferHeader("astraconductor.credential-transfer", 1, snapshot.VaultId,
        snapshot.StorageVersion, snapshot.AttemptId, transferId, snapshot.KeyId,
        new("AES-256-GCM", B64(nonce), 128), new("HKDF-SHA-256", B64(salt), B64(info), 32), 1);
      var plain = CanonicalJson.Of(snapshot);
      try
      {
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, cipher, tag, CanonicalJson.Of(header));
        return (new(header, B64(cipher), B64(tag)), "acm1_" + B64(migration));
      }
      finally { CryptographicOperations.ZeroMemory(plain); }
    }
    finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(migration); }
  }
  public static TransferSnapshot Unpack(TransferPackage package, string migrationKey)
  {
    var h = package.Header;
    Protocol.Require(migrationKey.StartsWith("acm1_", StringComparison.Ordinal) && migrationKey.Length == 48, "invalid-migration-key");
    Protocol.Require(h.Format == "astraconductor.credential-transfer" && h.Version == 1 && h.PayloadSchemaVersion == 1 &&
      h.Cipher.Name == "AES-256-GCM" && h.Cipher.TagLength == 128 && h.Kdf.Name == "HKDF-SHA-256" && h.Kdf.OutputLength == 32, "unsupported-crypto");
    var info = CanonicalJson.Of(new[] { "astraconductor.credential-transfer.v1", h.VaultId, h.StorageVersion, h.AttemptId, h.TransferId });
    var salt = Unb64(h.Kdf.Salt, 32);
    Protocol.Require(salt.Length == 32 && h.Kdf.Info == B64(info), "invalid-crypto-parameters");
    var migration = Unb64(migrationKey[5..], 32);
    var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, migration, 32, salt, info);
    byte[]? plain = null;
    try
    {
      plain = Decrypt(key, new(h.Cipher.Nonce, package.Ciphertext, package.Tag), CanonicalJson.Of(h));
      var snapshot = Protocol.Decode<TransferSnapshot>(Protocol.Parse(plain));
      Protocol.Require(snapshot.VaultId == h.VaultId && snapshot.StorageVersion == h.StorageVersion &&
        snapshot.AttemptId == h.AttemptId && snapshot.KeyId == h.KeyId && Unb64(snapshot.MasterKey, 32).Length == 32, "snapshot-mismatch");
      return snapshot;
    }
    finally
    {
      CryptographicOperations.ZeroMemory(migration);
      CryptographicOperations.ZeroMemory(key);
      if (plain is not null) CryptographicOperations.ZeroMemory(plain);
    }
  }
}
