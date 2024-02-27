using Newtonsoft.Json;

namespace CipherCracker.Api.Models;

public class AesGcmEncryptRequest
{
    [JsonProperty("plainText")]
    public string PlainText { get; set; }
    [JsonProperty("keyBase64")]
    public string KeyBase64 { get; set; }
    [JsonProperty("isIv12NullBytes")]
    public bool IsIv12NullBytes { get; set; }
}
