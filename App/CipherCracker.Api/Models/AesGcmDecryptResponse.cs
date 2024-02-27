using Newtonsoft.Json;

namespace CipherCracker.Api.Models;

public class AesGcmDecryptResponse : ResponseBase
{
    [JsonProperty("plainText")]
    public string PlainText { get; set; }
}
