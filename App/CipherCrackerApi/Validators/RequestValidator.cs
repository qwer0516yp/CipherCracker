using CipherCracker.Api.Models;
using CommunityToolkit.Diagnostics;

namespace CipherCracker.Api;

public static class RequestValidator
{
    public static void Validate(AesGcmEncryptRequest request)
    {
        Guard.IsNotNull(request);
        Guard.IsNotNullOrWhiteSpace(request.KeyBase64);
        Guard.IsNotNull(request.PlainText);
    }

    public static void Validate(AesGcmDecryptRequest request)
    {
        Guard.IsNotNull(request);
        Guard.IsNotNullOrWhiteSpace(request.KeyBase64);
        Guard.IsNotNullOrWhiteSpace(request.IvBase64);
        Guard.IsNotNullOrWhiteSpace(request.EncryptedMessageBase64);
    }
}
