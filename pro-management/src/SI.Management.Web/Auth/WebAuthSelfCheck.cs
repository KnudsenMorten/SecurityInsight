using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SI.Management.Web.Auth;

/// <summary>
/// Framework WEB-AUTH-SELF-CHECK-1: the ring-0 proof of the token-verification path with no person signing in. At web STARTUP,
/// before the listener opens, Microsoft's token library is loaded eagerly and the SAME validation path the app uses
/// (<see cref="BuiltInTokenVerifier.VerifyAsync"/>, through its fixed-key constructor) runs on SYNTHETIC tokens: a throw-away
/// RSA key, a random tenant id and a random app id -- nothing of the install is read or needed. Expected:
///   * ONE accepted: a person's ID token signed with the throw-away key (proves the whole path, not only the assembly load);
///   * FOUR refused, each BY Microsoft's library (the verifier's "the token is not valid" answer): expired by more than the
///     clock skew, another app's audience, signed with another key under the same key id, and unsigned (alg=none).
/// OK = one log line ("web auth self-check: OK ..."). Not OK (or the check did not run) = the app is UNHEALTHY: /healthz
/// answers 503, so the update's health check never sees 200 and the revision is not taken (fail closed).
/// Never throws.
/// </summary>
public static class WebAuthSelfCheck
{
    public const string OkPrefix = "web auth self-check: OK";
    public const string FailPrefix = "web auth self-check: FAILED";

    public sealed record Result(bool Ok, int Accepted, int Refused, string Line, IReadOnlyList<string> Failures);

    /// The verifier the check runs: the app's own class with fixed keys (tests hand in another one to prove the failure path).
    public delegate BuiltInTokenVerifier VerifierFactory(string tenantId, string clientId, IEnumerable<SecurityKey> keys);

    public static Result Run(VerifierFactory? factory = null) => RunAsync(factory).GetAwaiter().GetResult();

    public static async Task<Result> RunAsync(VerifierFactory? factory = null)
    {
        var failures = new List<string>();
        var accepted = 0; var refused = 0;
        string library = "unknown";
        try
        {
            library = LibraryVersion();
            var tenant = Guid.NewGuid().ToString();
            var client = Guid.NewGuid().ToString();
            using var rsa = RSA.Create(2048);
            var key = new RsaSecurityKey(rsa) { KeyId = "self-check-" + Guid.NewGuid().ToString("N") };
            using var otherRsa = RSA.Create(2048);
            var other = new RsaSecurityKey(otherRsa) { KeyId = key.KeyId };
            var verifier = (factory ?? ((t, c, k) => new BuiltInTokenVerifier(t, c, k)))(tenant, client, new SecurityKey[] { key });
            var oid = Guid.NewGuid().ToString();
            var now = DateTime.UtcNow;

            // 1 accepted: the full path, and the identity is the token's own
            var good = Mint(tenant, oid, now.AddMinutes(-5), now.AddMinutes(55), client, key);
            var (id, why) = await verifier.VerifyAsync(good, accessToken: false);
            if (id is not null && string.Equals(id.FindFirst("oid")?.Value, oid, StringComparison.OrdinalIgnoreCase)) accepted++;
            else failures.Add("a valid synthetic token was not accepted: " + (id is null ? why : "another object id"));

            // refused by Microsoft's library, each for its own reason
            var cases = new (string What, string Token, string? Reason)[]
            {
                ("expired", Mint(tenant, Guid.NewGuid().ToString(), now.AddMinutes(-80), now.AddMinutes(-20), client, key), "the token has expired"),
                ("wrong audience", Mint(tenant, Guid.NewGuid().ToString(), now.AddMinutes(-5), now.AddMinutes(55), Guid.NewGuid().ToString(), key), "another app's audience"),
                ("another key", Mint(tenant, Guid.NewGuid().ToString(), now.AddMinutes(-5), now.AddMinutes(55), client, other), "the signature is not the tenant's"),
                ("alg=none", Unsigned(tenant, client, now), null),
            };
            foreach (var (what, token, reason) in cases)
            {
                var (rid, rwhy) = await verifier.VerifyAsync(token, accessToken: false);
                var byLibrary = rid is null && rwhy.StartsWith("the token is not valid: ", StringComparison.Ordinal)
                                && (reason is null || rwhy.EndsWith(reason, StringComparison.Ordinal));
                if (byLibrary) refused++;
                else failures.Add(rid is not null ? $"the {what} synthetic token was ACCEPTED" : $"the {what} synthetic token was refused for another reason: {rwhy}");
            }
        }
        catch (Exception ex)
        {
            failures.Add("the check could not run: " + ex.GetType().Name + ": " + ex.Message);
        }

        var ok = failures.Count == 0 && accepted == 1 && refused == 4;
        var line = ok
            ? $"{OkPrefix} (1 accepted, 4 refused as expected; Microsoft.IdentityModel.JsonWebTokens {library} loaded)"
            : $"{FailPrefix} ({accepted} accepted, {refused} refused; Microsoft.IdentityModel.JsonWebTokens {library}): {string.Join("; ", failures)} -- /healthz answers 503";
        return new Result(ok, accepted, refused, line, failures);
    }

    /// The loaded token library's version (forces the assembly load).
    public static string LibraryVersion()
    {
        var asm = typeof(JsonWebTokenHandler).Assembly;
        return asm.GetName().Version?.ToString() ?? "unknown";
    }

    private static string Mint(string tenant, string oid, DateTime iat, DateTime exp, string aud, SecurityKey key) =>
        new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                ["oid"] = oid, ["tid"] = tenant, ["sub"] = "self-check", ["ver"] = "2.0",
                ["preferred_username"] = "self-check@example.invalid", ["name"] = "web auth self-check",
            },
            Issuer = $"https://login.microsoftonline.com/{tenant}/v2.0",
            Audience = aud,
            IssuedAt = iat, NotBefore = iat, Expires = exp,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        });

    private static string Unsigned(string tenant, string client, DateTime now) =>
        new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { ["oid"] = Guid.NewGuid().ToString(), ["tid"] = tenant, ["ver"] = "2.0" },
            Issuer = $"https://login.microsoftonline.com/{tenant}/v2.0",
            Audience = client,
            IssuedAt = now.AddMinutes(-5), NotBefore = now.AddMinutes(-5), Expires = now.AddMinutes(55),
        });
}

/// The result of the startup self-check, for /healthz. Not run (null) = unhealthy.
public sealed class WebAuthSelfCheckState
{
    public WebAuthSelfCheck.Result? Result { get; set; }
    public bool Healthy => Result?.Ok == true;
}
