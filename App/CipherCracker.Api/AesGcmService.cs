using CipherCracker.Api.Models;
using CipherCracker.ClassLibrary;

namespace CipherCracker.Api;

public class AesGcmService
{
    public AesGcmEncryptResponse ProcessEncryptionResquest(AesGcmEncryptRequest request)
    {
        var response = new AesGcmEncryptResponse();
        
        try
        {
            RequestValidator.Validate(request);

            var aesGcmManager = new AesGcmManager(request.KeyBase64, KeyStringFormat.Base64);
            var encryptedMessageBase64 = aesGcmManager.EncryptBlockBase64(request.PlainText, request.IsIv12NullBytes, out var ivBase64);

            response.IsSuccess = true;
            response.IvBase64 = ivBase64;
            response.IvHex = ivBase64.Base64StringToBytes().ToHexString();
            response.EncryptedMessageBase64 = encryptedMessageBase64;
            response.EncryptedMessageHex = encryptedMessageBase64.Base64StringToBytes().ToHexString();
        }
        catch (Exception ex) 
        {
            response.IsSuccess = false;
            response.ErrorMessage = ex.Message;
        }
        
        return response;
    }

    public AesGcmDecryptResponse ProcessDecryptionResquest(AesGcmDecryptRequest request)
    {
        var response = new AesGcmDecryptResponse();
        
        try 
        {
            RequestValidator.Validate(request);

            var aesGcmManager = new AesGcmManager(request.KeyBase64, KeyStringFormat.Base64);
            var decryptedMessage = aesGcmManager.DecryptBlockBase64(request.EncryptedMessageBase64, request.IvBase64);

            response.IsSuccess = true;
            response.PlainText = decryptedMessage;
        }
        catch (Exception ex) 
        {
            response.IsSuccess = false;
            response.ErrorMessage = ex.Message;
        }

        return response;
    }
}
