using System.Text;
using System.Text.Json;

namespace SIAnalyzer.Tests;

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

    /// <summary>GET and deserialize, case-insensitively so a camelCase API maps onto PascalCase
    /// test DTOs without each test restating the option.</summary>
    public static async Task<T?> GetFromJsonSafeAsync<T>(this HttpClient client, string url)
    {
        var json = await client.GetStringAsync(url);
        return JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    }
}
