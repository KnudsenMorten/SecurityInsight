using System.Text;
using System.Text.Json;

namespace Sia.Tests;

internal static class HttpHelpers
{
    private static readonly JsonSerializerOptions Opts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>POST a body as JSON without pulling in System.Net.Http.Json's content negotiation quirks.</summary>
    public static Task<HttpResponseMessage> PostAsJsonSafeAsync(this HttpClient client, string url, object body)
    {
        var json = JsonSerializer.Serialize(body, Opts);
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        return client.PostAsync(url, content);
    }
}
