using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Astra.Credentials;

/// <summary>Exact JSON decimal API levels. Values outside the .NET decimal domain are rejected, never rounded.</summary>
public static partial class ApiLevel
{
  private static readonly BigInteger MaximumCoefficient = BigInteger.Parse("79228162514264337593543950335", CultureInfo.InvariantCulture);
  [GeneratedRegex("^(0|[1-9][0-9]*)(?:\\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$", RegexOptions.CultureInvariant)]
  private static partial Regex NumberPattern();

  public static decimal Parse(string source)
  {
    var match = NumberPattern().Match(source);
    Protocol.Require(match.Success, "invalid-api-level");
    var fraction = match.Groups[2].Value;
    var digits = (match.Groups[1].Value + fraction).TrimStart('0');
    if (digits.Length == 0) return 0m;
    // A frame is at most 2 MiB: an exponent outside Int64 cannot cancel its finite coefficient length.
    var exponent = 0L;
    Protocol.Require(!match.Groups[3].Success || long.TryParse(match.Groups[3].Value, NumberStyles.AllowLeadingSign,
      CultureInfo.InvariantCulture, out exponent), "invalid-api-level");
    var trimmed = digits.TrimEnd('0');
    var scale = (BigInteger)fraction.Length - exponent - (digits.Length - trimmed.Length);
    digits = trimmed;
    Protocol.Require(scale <= 28 && scale >= -29, "invalid-api-level");
    if (scale < 0) { digits += new string('0', (int)-scale); scale = 0; }
    Protocol.Require(digits.Length <= 29, "invalid-api-level");
    var coefficient = BigInteger.Parse(digits, CultureInfo.InvariantCulture);
    Protocol.Require(coefficient <= MaximumCoefficient, "invalid-api-level");
    var low = (uint)(coefficient & uint.MaxValue);
    var middle = (uint)((coefficient >> 32) & uint.MaxValue);
    var high = (uint)(coefficient >> 64);
    return new decimal(unchecked((int)low), unchecked((int)middle), unchecked((int)high), false, (byte)scale);
  }
  public static string Format(decimal value)
  {
    Protocol.Require(value >= 0, "invalid-api-level");
    return value.ToString("0.############################", CultureInfo.InvariantCulture);
  }
}

public sealed class ApiLevelJsonConverter : JsonConverter<decimal>
{
  public override decimal Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
  {
    Protocol.Require(reader.TokenType == JsonTokenType.Number, "invalid-api-level");
    return ApiLevel.Parse(Encoding.UTF8.GetString(reader.HasValueSequence ? reader.ValueSequence.ToArray() : reader.ValueSpan));
  }
  public override void Write(Utf8JsonWriter writer, decimal value, JsonSerializerOptions options) =>
    writer.WriteRawValue(ApiLevel.Format(value));
}
