namespace CipherCracker.ClassLibrary.Test;

public class RsaUtilsTests
{
    private readonly string _sampleKeysRootPath = Environment.CurrentDirectory + @"\SampleKeys\RSA\";
    /**************************************************************************************************************************
     * Following OpenSSL commands are used to generate the test RSA keys in above folder.
     * 1. openssl req -x509 -newkey rsa:2048 -keyout "encryptedRsaPrivate_pkcs8.pem" -passout pass:test -out "selfSignedX509CertRsaPublic365Day2K.pem" -days 365 -subj /CN=OWEN/O=TEST/C=AU/ST=NSW/L=Sydney
     * 2. openssl rsa -in "encryptedRsaPrivate_pkcs8.pem" -out "unencryptedRsaPrivate_pkcs8.pem"
     * 3. openssl rsa -in "encryptedRsaPrivate_pkcs8.pem" -out "rsaPrivate_pkcs1.pem" -traditional
     * 4. openssl x509 -pubkey -noout -in "selfSignedX509CertRsaPublic365Day2K.pem" -out "rsaPublic.pem"
     **************************************************************************************************************************/

    //This test simulates RsaUtils reading a self signed X509 certificate string
    [Fact]
    public void LoadPublicKeyFromString_Success()
    {
        //selfSignedX509CertRsaPublic365Day2K.pem
        var testPublicCert = @"-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUZD/Y/oE/X/1JKmno0+axi+urf0MwDQYJKoZIhvcNAQEL
BQAwSjENMAsGA1UEAwwET1dFTjENMAsGA1UECgwEVEVTVDELMAkGA1UEBhMCQVUx
DDAKBgNVBAgMA05TVzEPMA0GA1UEBwwGU3lkbmV5MB4XDTI0MDQxNzA2MTEwNFoX
DTI1MDQxNzA2MTEwNFowSjENMAsGA1UEAwwET1dFTjENMAsGA1UECgwEVEVTVDEL
MAkGA1UEBhMCQVUxDDAKBgNVBAgMA05TVzEPMA0GA1UEBwwGU3lkbmV5MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAonhD9V3sWGwdtkbIQixmgIj2kuTt
Z2hiaLyL8QvpyeFbCyEGb85d/bQQi78xLQMelTFGl74CLAAneeLldIPNxT501XHn
fEll+KFDlSSstX+eddUwMzQ3TP6287nQMlB0mqCLX0YQWZPA/QMDDun6ou0UDCF6
HBVdRTptWTJ4uSf37IZJhPqzbc0YTJSHCmXJqAdeR4N2nK/e+V7NKFAse2V5nN1F
7vGp4y06UVccM/EcyH1NvOt7RztjVdIyLsld6s4NnGl8ujKzqL7TtXORGcowBm/2
c0BBIQpye1ET0aIiH4Me/gNGg5X1hJDNPo7WYKX76yJoSLMrWoSEoEMbawIDAQAB
o1MwUTAdBgNVHQ4EFgQU5vDkje8zANEaq/FHXAFBgE/DR/kwHwYDVR0jBBgwFoAU
5vDkje8zANEaq/FHXAFBgE/DR/kwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAfRIZjyQe6fNoFZFfKBC/+GUfkOG0Jh6gmkGACb3uw93QobXljSJA
qPIzQYPvMLp5bxifu9kpZ5ibFIiFsdKvb77uof/v/wAg3tTcoJwExfhTTi+YagF6
Qt7kncgrN8TwSzOe4NDkTtHJM6twbFwVowzIkvcjyWGdrg6MN2djb5nSgm/HQvUc
q/P+Tf97u9sAKcq/U1vB13YOzQJwQVkEpLTweG/KI35IW8N9Ob3BJl7YmrZCljNz
X9LxhoPWbZspWeVbQmEswXveGeiBtBolAiH+N9vUVazMUXT1MG5q2va38PQbcY9a
wGZ+2ReM18zF/GIyH/Szpstxbc3dE/FU0w==
-----END CERTIFICATE-----
";
        var rsaPublicKey = RsaUtils.LoadPublicKeyFromString(testPublicCert);
        rsaPublicKey.Should().NotBeNull();
        rsaPublicKey.KeySize.Should().Be(2048);

        var rsaPublicKeyFileLoaded = RsaUtils.LoadPublicKeyFromFile(_sampleKeysRootPath + "selfSignedX509CertRsaPublic365Day2K.pem");
        rsaPublicKeyFileLoaded.Should().NotBeNull();
        rsaPublicKeyFileLoaded.KeySize.Should().Be(2048);

        rsaPublicKey.Should().BeEquivalentTo(rsaPublicKeyFileLoaded);
    }
    
    [Fact]
    public void LoadPrivateKeyFromString_encryptedPkcs8_Success()
    {
        //encryptedRsaPrivate_pkcs8.pem
        var testRsaPrivateKey = @"-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJDBWBgkqhkiG9w0BBQ0wSTAxBgkqhkiG9w0BBQwwJAQQ8ZFilQYR5wbBE+45
RotuoAICCAAwDAYIKoZIhvcNAgkFADAUBggqhkiG9w0DBwQIf9+JVN1VXDcEggTI
x+2xGd4Cgbn0HMU/61hYIYFk20YxoCASivls6M0zbMRBBqic4WQ6AjNqtOF9FGmr
Va/QPIQFQrX+hhIxJXwxpDPkUZtFjHh5umBcJee/HzQwBAo8ojip4LEvkYT1Dhxa
m0kte75mZiw2r1XRvpC8abtC8rkAQGQ2XRft8UxiTH16OgGas+2WYQuYTwYHE9q2
jLmO9EarQrH5qSm6hI80r5eSzIP9Kk25QQAGk1E+z0HonOc3l8ARvYo7BrCCblsp
6obGv6dEQyha1AUe/YMFr/YyHSnEDhruhNuhQUgDlsByTq7rfnkx5P/uB5YCS6dY
JMbru6U91Iz6lgxvM/zQFiIkQmmLP6sEwMNEt7G7cTfa5X2DX7kgaHfiV4aMPelz
nm5c5o2vnhSebp9VstJTB67D+QA1n9lATB2MTxS+TUnawn6xQ1ImU3rcSpKneOr3
AEKuGKFiyXydPpV/jCKsUqN5WuvAYiXW//XA3PYhV691Gga+/sNzazkhF87nYFIr
J0jqSzoHgduC0XsxL1wXt6pkBkBf3SpkiqfpE+PUbzmJKY0tbrvxiTGh2i7UFqo7
6WLRqX1RPXRclnn7y8Tw7nB+GaOa91J1MFO6SMdmTNdiUpcwtQMFWzmoa0/33NPt
cvPD9GwwRBeFLvvBV/3nHpWP7MQhB1q/YKRQSzIRvaMEgWHZlPQmuZS+OcFU8A0D
mvvyNuVZjpJLDtiuEbYRqG73BKnXpGfl+8b+SSD1V7lGzjlc7hCu2yWW0nqV7FP/
URAeifwuEtKHidZwyccVFy+7bZ105Q2VlWg1vVA0lx0/utpeXRgd2xH3/q+lJrRu
YJMbMca0mlqhWx8IGBbzORQYq1S60BIX+byvmOb/ShJorGK6fsDetFRgzhc4Tgj+
gjFsKJD/Ru1KJOllbftLEQfHzDVj4F5JjQbcXlzahoFRln67dYGu2DkzyQFiJTTC
XLCHmWUJVCFfuUne18vr62K8i5vZOCcjbsWqXU4sqIXmCwuTRVNOdSBnHEN3n5gH
LDtpNViPZGHyKOYbc2C4LVSPKzrXaQNyp3Ax+DGzWrcZdEdMacSlXyI3/i7RWu2V
McoQBODWAuF8JbAEiTQnsFctgdML9Tfeka24mm8yt3acVVsCUyWeNkPpFQDUJ4xP
YxI1Q9Aq1t5nfhhZ/lMNDYQwNbUSckNJt+qILtDJCDpgQQMY5qJpgYYzt7W1Cutp
5Rrx0qlpzgZQLIbv3lEiph8uV0XxS5fFAk8CgA1ir8xajzsPTsY0q/8uTv3yILAp
VAmsgZpR3bmUw1h1cT/YDa4bXyi0rkLkrSBNToz4AoxXkxcEJilQQO2eAqxSjo/u
jgxH6winDd83/x7as/XduzM3OgpBwOGrWE0coZ7BVUanaYwTg/JpXCpnHFSwpC5f
pa9lnxjr+N8fDhuzppujiCUWRuEImvotQFHsgcNk+t4nBc2ocV+pRC0lkzc0QjB8
zrVuf1skyCrHudReQws2PylA70tTDxu8VVeZZc3CkvguWU+zSs/2oLOrpmXpj6Kz
wlKwSW/EfGiYhFSUQfMdT51VvFX9pZZCpHU3QKpP1f3ZbFzs/rZxHDb88YuKd8g4
Wd0wVFN6m331R5NEmhufGokW9JdJhPRS
-----END ENCRYPTED PRIVATE KEY-----
";
        var rsaPrivateKey = RsaUtils.LoadPrivateKeyFromString(testRsaPrivateKey, "test");
        rsaPrivateKey.Should().NotBeNull();
        rsaPrivateKey.KeySize.Should().Be(2048);
    }

    [Fact]
    public void LoadPrivateKeyFromString_unencryptedRsaPrivatePkcs8_rsaPrivatepkcs1_Success()
    {
        var testRsaPrivatePkcs1 = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAonhD9V3sWGwdtkbIQixmgIj2kuTtZ2hiaLyL8QvpyeFbCyEG
b85d/bQQi78xLQMelTFGl74CLAAneeLldIPNxT501XHnfEll+KFDlSSstX+eddUw
MzQ3TP6287nQMlB0mqCLX0YQWZPA/QMDDun6ou0UDCF6HBVdRTptWTJ4uSf37IZJ
hPqzbc0YTJSHCmXJqAdeR4N2nK/e+V7NKFAse2V5nN1F7vGp4y06UVccM/EcyH1N
vOt7RztjVdIyLsld6s4NnGl8ujKzqL7TtXORGcowBm/2c0BBIQpye1ET0aIiH4Me
/gNGg5X1hJDNPo7WYKX76yJoSLMrWoSEoEMbawIDAQABAoIBADRt9RhQd/3M3gW9
b9CS/X0LNe8Pe2E8eU1tUwe1nXttgvDjdm1MPl6p5hEC4P6ynALvROWhBphmcFbQ
FtXz1sqJLjDXMimUkhibCfEuRaHIjj1eT9CmUBZDuIyMcRhbiFWB65gSRyJxIP1F
JI6CiURcl3SWtQ4tAs1dXn5DYFv3enxxM8UiZm9z9Pchoxkm+IaI5CbCrl7uTMJ6
GGIPmTiQV+8aa63qg8qGs+hLYQNtt2S7VmREZFCN4yljgDBqoxXL2O6YW22pE3ZT
ljDnQtV3NdlfzMFD91cZrN6ipN/b+YMTF7ree+mL4N02O5dV6hfqSEmma5qghgBu
1XJm6LECgYEA5GUGPZhbhzI3dVrajrFVRHqifKKTDBURaYmwTjgEPWEnkcOMwVJ9
uH9NjgMCRhhS9m+5jUyIbLIs+8USuGV1O/NFIRnYCnyq6skYNx0xYyFz863JirPU
LWG27x036WC1s5rNuFv8c9f2Dj7fHQ1fzGDnVdxnw4HdPC+pcJWYqTkCgYEAthtl
2YRHM6qwFHjd7hkN+27c3a2ewcjLSSkNl1oK5IJPbVU5lRsKVXuFJlH+4MAJpx8/
NHdfuJ24gG/gP3rIt9EH7bP5wFCTsbA/p+gYTQWK3NiZkHK05zOgf6wCZBCiJC75
//+g/VnP7fDW+QfaQNjS6+CstUyEahDbay4E3cMCgYAElEn1vjJHmagnADVVmxSc
lODhItlT6rA4r3wLdXAQUvxaHdOapK7EnjjN2h2XjjFLo53SyXAKzd+9BIyFifM5
ynzeVwhP3YQHxRRpNnqhBDCw+BEMaOKeLlFepfVTBo9eFIJ/aci8Ad57FqOej4AW
NvMsc4jZEKeA52u8SCORcQKBgGjeJiy4i/go1vUzFTpDm1WrZe0SSlX1t3sN9RGv
fI5SrEKdzWccBztqwiZrGYd7jxN6Xv9rrue1i8YKpuxnXKbd7N7pwW0J+cNdZ4rd
kQDprCm5YdVY+OwbQtXCzC2rlnOXyceuAZtj2OWAx4rpBrpJIk1LOKm+wpIB2xlB
ivPZAoGBAMjvAsE33Y/7oFVWDGm38wzvFB9x0E6vqxF32xIvxdrvh8v7YYYccRpx
CKDOOKLhCm7pVIsUc/Y3Vq9veci7M6Vl3qBFZt6yPj1juzMX6bDC1qzOO2QUOB4v
lglxWoYYXfFAR29Yl8u96Ne98gEz0FQzc67YIeCPxV0OL4+o09gu
-----END RSA PRIVATE KEY-----
";
        var testRsaPrivateUnencryptedPkcs8 = @"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCieEP1XexYbB22
RshCLGaAiPaS5O1naGJovIvxC+nJ4VsLIQZvzl39tBCLvzEtAx6VMUaXvgIsACd5
4uV0g83FPnTVced8SWX4oUOVJKy1f5511TAzNDdM/rbzudAyUHSaoItfRhBZk8D9
AwMO6fqi7RQMIXocFV1FOm1ZMni5J/fshkmE+rNtzRhMlIcKZcmoB15Hg3acr975
Xs0oUCx7ZXmc3UXu8anjLTpRVxwz8RzIfU2863tHO2NV0jIuyV3qzg2caXy6MrOo
vtO1c5EZyjAGb/ZzQEEhCnJ7URPRoiIfgx7+A0aDlfWEkM0+jtZgpfvrImhIsyta
hISgQxtrAgMBAAECggEANG31GFB3/czeBb1v0JL9fQs17w97YTx5TW1TB7Wde22C
8ON2bUw+XqnmEQLg/rKcAu9E5aEGmGZwVtAW1fPWyokuMNcyKZSSGJsJ8S5FociO
PV5P0KZQFkO4jIxxGFuIVYHrmBJHInEg/UUkjoKJRFyXdJa1Di0CzV1efkNgW/d6
fHEzxSJmb3P09yGjGSb4hojkJsKuXu5MwnoYYg+ZOJBX7xprreqDyoaz6EthA223
ZLtWZERkUI3jKWOAMGqjFcvY7phbbakTdlOWMOdC1Xc12V/MwUP3Vxms3qKk39v5
gxMXut576Yvg3TY7l1XqF+pISaZrmqCGAG7VcmbosQKBgQDkZQY9mFuHMjd1WtqO
sVVEeqJ8opMMFRFpibBOOAQ9YSeRw4zBUn24f02OAwJGGFL2b7mNTIhssiz7xRK4
ZXU780UhGdgKfKrqyRg3HTFjIXPzrcmKs9QtYbbvHTfpYLWzms24W/xz1/YOPt8d
DV/MYOdV3GfDgd08L6lwlZipOQKBgQC2G2XZhEczqrAUeN3uGQ37btzdrZ7ByMtJ
KQ2XWgrkgk9tVTmVGwpVe4UmUf7gwAmnHz80d1+4nbiAb+A/esi30Qfts/nAUJOx
sD+n6BhNBYrc2JmQcrTnM6B/rAJkEKIkLvn//6D9Wc/t8Nb5B9pA2NLr4Ky1TIRq
ENtrLgTdwwKBgASUSfW+MkeZqCcANVWbFJyU4OEi2VPqsDivfAt1cBBS/Fod05qk
rsSeOM3aHZeOMUujndLJcArN370EjIWJ8znKfN5XCE/dhAfFFGk2eqEEMLD4EQxo
4p4uUV6l9VMGj14Ugn9pyLwB3nsWo56PgBY28yxziNkQp4Dna7xII5FxAoGAaN4m
LLiL+CjW9TMVOkObVatl7RJKVfW3ew31Ea98jlKsQp3NZxwHO2rCJmsZh3uPE3pe
/2uu57WLxgqm7Gdcpt3s3unBbQn5w11nit2RAOmsKblh1Vj47BtC1cLMLauWc5fJ
x64Bm2PY5YDHiukGukkiTUs4qb7CkgHbGUGK89kCgYEAyO8CwTfdj/ugVVYMabfz
DO8UH3HQTq+rEXfbEi/F2u+Hy/thhhxxGnEIoM44ouEKbulUixRz9jdWr295yLsz
pWXeoEVm3rI+PWO7MxfpsMLWrM47ZBQ4Hi+WCXFahhhd8UBHb1iXy73o173yATPQ
VDNzrtgh4I/FXQ4vj6jT2C4=
-----END PRIVATE KEY-----
";
        //loading pkcs1 & unencrypted pkcs8 does NOT require passphrase
        var rsaPrivatePkcs1Key = RsaUtils.LoadPrivateKeyFromString(testRsaPrivatePkcs1, string.Empty);
        rsaPrivatePkcs1Key.Should().NotBeNull();
        rsaPrivatePkcs1Key.KeySize.Should().Be(2048);

        var rsaPrivatePkcs8Key = RsaUtils.LoadPrivateKeyFromString(testRsaPrivateUnencryptedPkcs8, string.Empty);
        rsaPrivatePkcs8Key.Should().NotBeNull();
        rsaPrivatePkcs8Key.KeySize.Should().Be(2048);

        rsaPrivatePkcs1Key.Should().BeEquivalentTo(rsaPrivatePkcs8Key);
    }
}
