using Newtonsoft.Json;

namespace CipherCracker.Api.Models;

public class AesGcmEncryptResponse : ResponseBase
{
    [JsonProperty("encryptedMessageBase64")]
    public string EncryptedMessageBase64 { get; set; }
    [JsonProperty("encryptedMessageHex")]
    public string EncryptedMessageHex { get; set; }
    [JsonProperty("ivBase64")]
    public string IvBase64 { get; set; }
    [JsonProperty("ivHex")]
    public string IvHex { get; set; }
}
