using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CipherCracker.ClassLibrary;

public class AesGcmManager : IAesGcmManager
{
    private readonly byte[] _key;
    private const int MAC_BIT_SIZE = 128;         // Mac size is fixed to 128 bit for AES-GCM irregardless of key size

    public AesGcmManager(byte[] key)
    {
        _key = key;
    }

    public AesGcmManager(string keyString, KeyStringFormat format)
    {
        if (format == KeyStringFormat.Base64) { _key = Convert.FromBase64String(keyString); return; };
        if (format == KeyStringFormat.Hex) { _key = Convert.FromHexString(keyString); return; };
        throw new NotSupportedException("Unsupported key string format");
    }

    public byte[] Encrypt(byte[] plainTextBytes, byte[] ivBytes)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(_key), MAC_BIT_SIZE, ivBytes);
        cipher.Init(true, parameters);

        //AES GCM Generate Cipher Text With Auth Tag
        var cipherTextWithAuthTagBytes = new byte[cipher.GetOutputSize(plainTextBytes.Length)];
        var offset = cipher.ProcessBytes(plainTextBytes, 0, plainTextBytes.Length, cipherTextWithAuthTagBytes, 0);
        cipher.DoFinal(cipherTextWithAuthTagBytes, offset);

        return cipherTextWithAuthTagBytes;
    }

    public byte[] Decrypt(byte[] encryptedContentBytes, byte[] ivBytes)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(_key), MAC_BIT_SIZE, ivBytes);
        cipher.Init(false, parameters);

        var plainTextBytes = new byte[cipher.GetOutputSize(encryptedContentBytes.Length)];
        var len = cipher.ProcessBytes(encryptedContentBytes, 0, encryptedContentBytes.Length, plainTextBytes, 0);
        cipher.DoFinal(plainTextBytes, len);

        return plainTextBytes;
    }

    public string EncryptBlockBase64(string plainText, bool isIv12NullBytes, out string ivBase64)
    {
        var ivBytes = new byte[12];
        if(!isIv12NullBytes) 
            ivBytes = CryptoUtils.GenerateIvBytes();
        
        ivBase64 = ivBytes.ToBase64String();
        return Encrypt(Encoding.UTF8.GetBytes(plainText), ivBytes).ToBase64String();
    }

    public string DecryptBlockBase64(string encryptedBlockBase64, string ivBase64)
    {
        if(!encryptedBlockBase64.IsBase64String() || !ivBase64.IsBase64String())
            throw new ArgumentException("Invalid base64 string");

        return Decrypt(encryptedBlockBase64.Base64StringToBytes(), ivBase64.Base64StringToBytes()).ToUtf8String();
    }

    public string EncryptBlockHex(string plainText, bool isIv12NullBytes, out string ivHex)
    {
        var ivBytes = new byte[12];
        if (!isIv12NullBytes)
            ivBytes = CryptoUtils.GenerateIvBytes();

        ivHex = ivBytes.ToHexString();
        return Encrypt(Encoding.UTF8.GetBytes(plainText), ivBytes).ToHexString();
    }

    public string DecryptBlockHex(string encryptedBlockHex, string ivHex)
    {
        return Decrypt(encryptedBlockHex.HexStringToBytes(), ivHex.HexStringToBytes()).ToUtf8String();
    }
}
