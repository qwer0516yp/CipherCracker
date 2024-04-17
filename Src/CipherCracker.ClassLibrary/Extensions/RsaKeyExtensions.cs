namespace CipherCracker.ClassLibrary;

public static class RsaKeyExtensions
{
    public static RSA ToRSA(this AsymmetricKeyParameter privateKeyParameter)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)privateKeyParameter));
        return rsa;
    }
}
