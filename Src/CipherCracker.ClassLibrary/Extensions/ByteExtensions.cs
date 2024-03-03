using Org.BouncyCastle.Utilities.Encoders;

namespace CipherCracker.ClassLibrary;

public static class ByteExtensions
{
    public static string ToHexString(this byte[] data) => Hex.ToHexString(data);
    public static string ToBase64String(this byte[] data) => Convert.ToBase64String(data);
    public static string ToUtf8String(this byte[] data) => Encoding.UTF8.GetString(data);
}
