using Newtonsoft.Json;

namespace CipherCracker.Api.Models;

public class AesGcmDecryptRequest
{
    [JsonProperty("encryptedMessageBase64")]
    public string EncryptedMessageBase64 { get; set; }
    [JsonProperty("ivBase64")]
    public string IvBase64 { get; set; }
    [JsonProperty("keyBase64")]
    public string KeyBase64 { get; set; }
}
