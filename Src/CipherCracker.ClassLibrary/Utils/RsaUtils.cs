using System.Security.Cryptography.X509Certificates;

namespace CipherCracker.ClassLibrary;

public static class RsaUtils
{
    /// <summary>
    /// Load public key from file. File should be a certificate in PEM format
    /// </summary>
    /// <param name="certificateFilePath"></param>
    /// <returns></returns>
    public static RSA LoadPublicKeyFromFile(string certificateFilePath) => new X509Certificate2(certificateFilePath).GetRSAPublicKey()!;

    /// <summary>
    /// Load RSA public key from a public cert string value.
    /// </summary>
    /// <param name="publicCert"></param>
    /// <returns></returns>
    public static RSA LoadPublicKeyFromString(string publicCert) => new X509Certificate2(Encoding.Default.GetBytes(publicCert)).GetRSAPublicKey()!;

    /// <summary>
    /// Load private key from file. File should be private key in either PEM format
    /// </summary>
    /// <param name="privateKeyFile"></param>
    /// <param name="privateKeyPassphrase"></param>
    /// <returns></returns>
    public static RSA LoadPrivateKeyFromFile(string privateKeyFilePath, string password)
    {
        string privateKey = File.ReadAllText(privateKeyFilePath);
        return LoadPrivateKeyFromString(privateKey, password);
    }

    /// <summary>
    /// Load private key from string. File should be private key in either pkcs1 or pkcs8 format.
    /// </summary>
    /// <param name="privateKey"></param>
    /// <param name="password"></param>
    /// <returns></returns>
    public static RSA LoadPrivateKeyFromString(string privateKey, string password)
    {
        object keyPair;
        using (StringReader srPk = new StringReader(privateKey))
        {
            PemReader pemReader = string.IsNullOrEmpty(password) ? new PemReader(srPk) : new PemReader(srPk, new PasswordFinder(password));
            keyPair = pemReader.ReadObject();
        }

        //pkcs1, -----BEGIN RSA PRIVATE KEY-----
        if (keyPair is AsymmetricCipherKeyPair)
        {
            return ((AsymmetricCipherKeyPair)keyPair).Private.ToRSA();
        }
        //pkcs8,
        //Unencrypted:  -----BEGIN PRIVATE KEY----- 
        //Encrypted:    -----BEGIN ENCRYPTED PRIVATE KEY-----
        if (keyPair is AsymmetricKeyParameter)
        {
            return ((AsymmetricKeyParameter)keyPair).ToRSA();
        }
        
        throw new InvalidOperationException("Invalid private key format.");
    }
}
