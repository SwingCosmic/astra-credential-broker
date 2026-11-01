using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Astra.Credentials;
using Xunit;

namespace Broker.Tests;

public sealed class ProtocolCryptoTests
{
  private sealed record InteropVector(string MigrationKey, TransferSnapshot Snapshot, TransferPackage Package);
  [Fact]
  public void JavaScriptVectorDecryptsAndDotnetVectorIsExportedForReverseValidation()
  {
    var vector = Protocol.Decode<InteropVector>(Protocol.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "vectors", "transfer-v1.json"))));
    Assert.Equal("\u2028\u2029\U0001f600<>&", vector.Snapshot.Records[0].Description.Metadata["界"]);
    Assert.Equal(Crypto.HashObject(vector.Snapshot), Crypto.HashObject(Crypto.Unpack(vector.Package, vector.MigrationKey)));
    var (package, migration) = Crypto.Pack(vector.Snapshot);
    File.WriteAllBytes(Path.Combine(AppContext.BaseDirectory, "interop-dotnet.json"), Protocol.Encode(new InteropVector(migration, vector.Snapshot, package)));
  }
  [Theory]
  [InlineData("{\"a\":1,\"a\":2}")]
  [InlineData("{\"x\":[{\"a\":true,\"a\":false}]}")]
  public void DuplicatePropertiesRejected(string json) => Assert.Equal("duplicate-property",
    Assert.Throws<BrokerException>(() => Protocol.Parse(Encoding.UTF8.GetBytes(json))).Code);

  [Theory]
  [InlineData("true")]
  [InlineData("42")]
  [InlineData("null")]
  [InlineData("[]")]
  [InlineData("{}")]
  public void MetadataValuesAreStrictStrings(string value)
  {
    var json = Protocol.Parse(Encoding.UTF8.GetBytes("{\"metadata\":{\"a\":" + value + "},\"payload\":\"\",\"contentType\":\"x\",\"payloadFormatVersion\":1}"));
    Assert.ThrowsAny<Exception>(() => Protocol.Metadata(Protocol.Decode<RecordBody>(json).Metadata));
  }
  [Fact]
  public void MetadataBoundsUseCanonicalUtf8()
  {
    Protocol.Metadata(Enumerable.Range(0, 64).ToDictionary(i => "k" + i, _ => ""));
    Assert.Throws<BrokerException>(() => Protocol.Metadata(Enumerable.Range(0, 65).ToDictionary(i => "k" + i, _ => "")));
    Protocol.Metadata(new() { [new string('界', 42) + "aa"] = new string('界', 341) + "a" });
    Assert.Throws<BrokerException>(() => Protocol.Metadata(new() { [new string('界', 43)] = "" }));
    Assert.Throws<BrokerException>(() => Protocol.Metadata(new() { ["a"] = new string('界', 342) }));
    Assert.Throws<BrokerException>(() => Protocol.Metadata(Enumerable.Range(0, 17).ToDictionary(i => "k" + i, _ => new string('a', 1024))));
    Protocol.Metadata(new() { ["extension"] = "{\"nested\":false}" });
    Assert.Throws<BrokerException>(() => Protocol.Metadata(null));
    Assert.Throws<BrokerException>(() => Protocol.Metadata(new() { ["a"] = null! }));
    var exact = Enumerable.Range(0, 16).ToDictionary(i => "key" + i, i => i < 15 ? new string('a', 1024) : "");
    exact["key15"] = new string('a', 16 * 1024 - CanonicalJson.Of(exact).Length);
    Assert.Equal(16 * 1024, CanonicalJson.Of(exact).Length);
    Protocol.Metadata(exact);
    exact["key15"] += "a";
    Assert.Throws<BrokerException>(() => Protocol.Metadata(exact));
  }
  [Fact]
  public void StructuralSchemaHasResolvableReferencesAndStrictConstructorFields()
  {
    var schema = ProtocolSchema.Build();
    Assert.NotNull(schema["$defs"]?["CommitUpdate"]);
    var json = JsonSerializer.SerializeToElement(schema, Protocol.Json);
    void Walk(JsonElement node)
    {
      if (node.ValueKind == JsonValueKind.Object)
      {
        if (node.TryGetProperty("$ref", out var reference))
        {
          var target = json;
          foreach (var segment in reference.GetString()![2..].Split('/'))
            target = target.GetProperty(segment.Replace("~1", "/", StringComparison.Ordinal).Replace("~0", "~", StringComparison.Ordinal));
          Assert.NotEqual(JsonValueKind.Undefined, target.ValueKind);
        }
        foreach (var property in node.EnumerateObject()) Walk(property.Value);
      }
      else if (node.ValueKind == JsonValueKind.Array) foreach (var child in node.EnumerateArray()) Walk(child);
    }
    Walk(json);
    Assert.Throws<JsonException>(() => Protocol.Decode<BeginUpdate>(Protocol.Parse("{}"u8.ToArray())));
    Assert.Throws<JsonException>(() => Protocol.Decode<RecordBody>(Protocol.Parse("{\"contentType\":\"custom\",\"payloadFormatVersion\":\"1\",\"payload\":\"\",\"metadata\":{}}"u8.ToArray())));
  }
  [Fact]
  public async Task InvalidFrameLengthIsRejectedBeforeAllocatingPayload()
  {
    using var bytes = new MemoryStream(BitConverter.GetBytes(Protocol.MaxMessageBytes + 1));
    var error = await Assert.ThrowsAsync<BrokerException>(() => PipeProtocol.Read<RpcRequest>(bytes, CancellationToken.None));
    Assert.Equal("message-too-large", error.Code);
  }
  [Theory]
  [InlineData("01")]
  [InlineData("-1")]
  [InlineData("1.0")]
  [InlineData("9223372036854775808")]
  [InlineData("")]
  public void RevisionsAreDecimalInt64Strings(string revision) => Assert.Throws<BrokerException>(() => Protocol.Revision(revision));

  [Theory]
  [InlineData("Zg==")]
  [InlineData("Zh")]
  [InlineData("+")]
  public void NoncanonicalBase64Rejected(string value) => Assert.Throws<BrokerException>(() => Crypto.Unb64(value));

  [Fact]
  public void CanonicalJsonUsesUtf16OrderAndEcmaStringEscapes()
  {
    var input = Protocol.Parse(Encoding.UTF8.GetBytes("{\"z\":\"<>&\u2028\u2029😀\",\"a\":\"\\u0000\\n\\t\",\"💡\":1,\"界\":2}"));
    var expected = "{\"a\":\"\\u0000\\n\\t\",\"z\":\"<>&\u2028\u2029😀\",\"界\":2,\"💡\":1}";
    Assert.Equal(expected, Encoding.UTF8.GetString(CanonicalJson.Bytes(input)));
    Assert.Throws<BrokerException>(() => CanonicalJson.Bytes(Protocol.Parse("0.5"u8.ToArray())));
  }
  [Fact]
  public void HkdfRfc5869Vector()
  {
    var actual = HKDF.DeriveKey(HashAlgorithmName.SHA256, Enumerable.Repeat((byte)0x0b, 22).ToArray(), 42,
      Convert.FromHexString("000102030405060708090a0b0c"), Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9"));
    Assert.Equal("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", Convert.ToHexStringLower(actual));
  }
  [Fact]
  public void AesGcmNistVector()
  {
    var sealedValue = new SealedBytes(Crypto.B64(new byte[12]), Crypto.B64(Convert.FromHexString("cea7403d4d606b6e074ec5d3baf39d18")),
      Crypto.B64(Convert.FromHexString("d0d1c8a799996bf0265b98b5d48ab919")));
    Assert.Equal(new byte[16], Crypto.Decrypt(new byte[32], sealedValue, []));
    Assert.ThrowsAny<CryptographicException>(() => Crypto.Decrypt(new byte[32], sealedValue, [1]));
  }
  [Fact]
  public void TransferRoundTripAuthenticatesEveryHeaderAndKey()
  {
    var snapshot = new TransferSnapshot("vault", "version", "attempt", "key", Crypto.B64(RandomNumberGenerator.GetBytes(32)), []);
    var (package, migration) = Crypto.Pack(snapshot);
    Assert.Equal(Crypto.HashObject(snapshot), Crypto.HashObject(Crypto.Unpack(package, migration)));
    Assert.Equal(48, migration.Length);
    Assert.ThrowsAny<Exception>(() => Crypto.Unpack(package, "acm1_" + Crypto.B64(new byte[32])));
    Assert.ThrowsAny<Exception>(() => Crypto.Unpack(package with { Header = package.Header with { KeyId = "other" } }, migration));
    Assert.Throws<BrokerException>(() => Crypto.Unpack(package with { Header = package.Header with { Kdf = package.Header.Kdf with { OutputLength = 64 } } }, migration));
    var encoded = Protocol.Encode(package);
    var json = Encoding.UTF8.GetString(encoded).Replace("\"tagLength\":128", "\"tagLength\":128,\"unknown\":true", StringComparison.Ordinal);
    Assert.Throws<JsonException>(() => Protocol.Decode<TransferPackage>(Protocol.Parse(Encoding.UTF8.GetBytes(json))));
  }
}
