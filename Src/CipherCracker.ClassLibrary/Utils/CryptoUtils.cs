namespace CipherCracker.ClassLibrary;

public static class CryptoUtils
{
    public static byte[] GenerateIvBytes(int size = 16)
    {
        if (size < 12)
            throw new ArgumentException("IV must be at least 12 bytes", nameof(size));

        return GenerateRandomBytes(size);
    }

    public static byte[] GenerateRandomBytes(int size)
    {
        byte[] ivBytes = new byte[size];
        new SecureRandom().NextBytes(ivBytes);
        return ivBytes;
    }
}
