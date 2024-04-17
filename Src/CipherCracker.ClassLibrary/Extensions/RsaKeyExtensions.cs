namespace CipherCracker.ClassLibrary;

public static class RsaKeyExtensions
{
    public static RSA ToRSA(this AsymmetricKeyParameter privateKeyParameter) => DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)privateKeyParameter);
}
