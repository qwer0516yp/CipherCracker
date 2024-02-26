using Org.BouncyCastle.Utilities.Encoders;

namespace CipherCracker.ClassLibrary;

public static class StringExtensions
{
    public static bool IsBase64String(this string base64) => Convert.TryFromBase64String(base64, new Span<byte>(new byte[base64.Length]), out _);
    public static byte[] HexStringToBytes(this string hexString) => Hex.Decode(hexString);
    public static byte[] Base64StringToBytes(this string base64String) => Convert.FromBase64String(base64String);
}
