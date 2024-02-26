using System.Text;

namespace CipherCracker.ClassLibrary.Test;

public class AesGcmManagerTest
{
    [Fact]
    public void Encrypt_Decrypt_Success()
    {
        //Arrange
        var plainText = "Inhale confidence, exhale doubt.";
        var aesKeyBytes = CryptoUtils.GenerateRandomBytes(32);
        var aesGcmManager = new AesGcmManager(aesKeyBytes);
        var ivBytes = CryptoUtils.GenerateIvBytes();

        //Act
        var encryptedContentBytes = aesGcmManager.Encrypt(Encoding.UTF8.GetBytes(plainText), ivBytes);
        encryptedContentBytes.Should().NotBeNull();
        var decryptedContentBytes = aesGcmManager.Decrypt(encryptedContentBytes, ivBytes);
        var decryptedContent = Encoding.UTF8.GetString(decryptedContentBytes);

        //Assert
        decryptedContent.Should().Be(plainText);
    }

    [Fact]
    public void Decrypt_Success()
    {
        //Arrange
        var aesKeyBytes = "233f8ce4ac6aa125927ccd98af5750d08c9c61d98a3f5d43cbf096b4caaebe80".HexStringToBytes();
        var ivBytes = "2f3849399c60cb04b923bd33265b81c7".HexStringToBytes();
        //cipherText + authTag/MAC
        var encryptedContentBytes = ("1334cd5d487f7f47924187c94424a2079656838e063e5521e7779e441aa513de268550a89917fbfb0492fc" + "af453a410d142bc6f926c0f3bc776390").HexStringToBytes();

        var aesGcmManager = new AesGcmManager(aesKeyBytes);

        //Act
        var plainTextBytes = aesGcmManager.Decrypt(encryptedContentBytes, ivBytes);

        //Assert
        var plainText = Encoding.UTF8.GetString(plainTextBytes);
        plainText.Should().Be("Message for AES-256-GCM + Scrypt encryption");
    }
}
