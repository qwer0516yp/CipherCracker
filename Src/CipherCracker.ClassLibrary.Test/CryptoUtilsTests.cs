namespace CipherCracker.ClassLibrary.Test;

public class CryptoUtilsTests
{
    [Fact]
    public void GenerateIvBytes_RandomizedAs16Bytes_Success()
    {
        var ivBytes = CryptoUtils.GenerateIvBytes();
        ivBytes.Should().NotBeNull();
        ivBytes.Should().HaveCount(16);

        var ivBytes2 = CryptoUtils.GenerateIvBytes();
        ivBytes2.Should().NotBeNull();
        ivBytes2.Should().NotBeEquivalentTo(ivBytes);
    }
}