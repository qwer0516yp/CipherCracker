using Newtonsoft.Json;

namespace CipherCracker.Api.Models;

public class ResponseBase
{
    [JsonProperty("isSuccess")]
    public bool IsSuccess { get; set; }
    [JsonProperty("errorMessage")]
    public string ErrorMessage { get; set; }
}