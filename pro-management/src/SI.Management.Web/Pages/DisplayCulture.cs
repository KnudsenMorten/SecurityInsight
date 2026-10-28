using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Localization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Primitives;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages;

/// <summary>
/// Numbers on screen follow the VIEWER's regional format (operator, 2026-10-04: "numbers show as 12.205 in denmark and
/// 12,205 in usa"; framework BRAND-2.6). The display culture (CurrentUICulture) is chosen, in this order:
///   1. the viewer's own <b>Number format</b> choice (the user menu in the header; a cookie, per browser);
///   2. the installation default, the web-app setting <c>SIWeb_NumberFormatDefault</c> (when not "auto");
///   3. Automatic: the browser's Accept-Language among <see cref="Supported"/>, falling back to en-US.
/// 🔴 Accept-Language carries the browser's LANGUAGE, not the Windows regional format: an English browser on a
/// Danish-region PC says en-US. That is why step 1 exists -- Automatic alone gets exactly that case wrong.
/// The shared formatters (<see cref="Fmt"/>, <see cref="SI.Management.Core.ProData.ScoreFormat"/>) format with the
/// result, and the layout hands it to the browser (<c>&lt;html data-number-locale&gt;</c>) for charts and tables.
/// 🔒 CurrentCulture stays en-US on purpose: it is what model binding PARSES form numbers with, and a Danish browser
/// must not turn a posted "0.5" into 5. Only the display follows the viewer. CSV stays invariant; Excel keeps numbers.
/// </summary>
public static class DisplayCulture
{
    public const string Fallback = "en-US";
    public const string Auto = "auto";
    public static readonly string[] Supported = ["en-US", "da-DK", "en-GB", "de-DE", "sv-SE", "nb-NO"];

    /// The per-browser choice.
    public const string Cookie = "si-number-format";
    /// The installation-wide default (a web-app setting, scope engine:management-web).
    public const string Setting = "SIWeb_NumberFormatDefault";

    /// The choices a person picks from, in menu order: value -> label (with an example of the format).
    public static readonly IReadOnlyList<(string Value, string Label)> Choices =
    [
        (Auto, "Automatic (browser language)"),
        ("da-DK", "Danish (1.234,5)"),
        ("en-US", "English US (1,234.5)"),
        ("en-GB", "English UK (1,234.5)"),
        ("de-DE", "German (1.234,5)"),
        ("sv-SE", "Swedish (1 234,5)"),
        ("nb-NO", "Norwegian (1 234,5)"),
    ];

    /// A supported culture name (case-insensitive) in its canonical spelling, else null. "auto" is not a culture.
    public static string? Canonical(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : Supported.FirstOrDefault(s => s.Equals(value.Trim(), StringComparison.OrdinalIgnoreCase));

    /// A valid choice (a supported culture or "auto") in canonical spelling, else null.
    public static string? Choice(string? value) =>
        value is not null && value.Trim().Equals(Auto, StringComparison.OrdinalIgnoreCase) ? Auto : Canonical(value);

    /// What the viewer has chosen in this browser ("auto" when nothing or something unknown).
    public static string ChosenBy(HttpContext ctx) => Choice(ctx.Request.Cookies[Cookie]) ?? Auto;

    /// The locale name the browser formats with (charts, sortable tables): the display culture of this request.
    public static string Locale => CultureInfo.CurrentUICulture.Name is { Length: > 0 } n ? n : Fallback;

    /// The catalog entry: shown and changed on the Settings page like every web-app setting.
    public static readonly CatalogSetting Catalog = new()
    {
        Name = Setting, Label = "Number format (default for everyone)", Group = "Web app", Type = "enum",
        Values = Choices.Select(c => c.Value).ToArray(), Engines = new[] { "management-web" }, Edition = "pro", WebOnly = true,
        Default = JsonDocument.Parse("\"auto\"").RootElement.Clone(),
        Description = "How numbers are written on screen for a person who has not chosen their own format in the user menu: auto (from the browser's language), da-DK (1.234,5), en-US (1,234.5), en-GB, de-DE, sv-SE or nb-NO.",
        Purpose = "Sets the thousands and decimal separators everyone sees by default, so a Danish organisation reads 1.234,5 even in an English browser.",
        DefaultText = "auto: from the browser's language -- an English browser shows 1,234.5 even on a Danish PC",
        Effect = "Changes how every number on screen is written for people who have not picked their own format. Each person can still choose their own in the user menu. Exports (CSV, Excel) are not affected.",
        WhenToChange = "Once, when most readers use an English browser but read numbers the local way (for example a Danish organisation).",
    };

    public static RequestLocalizationOptions Options()
    {
        // a browser that sends only the language ("da") gets that language's number format too
        var cultures = Supported.Concat(new[] { "en", "da", "de", "sv", "nb" }).Select(c => new CultureInfo(c)).ToList();
        var o = new RequestLocalizationOptions
        {
            DefaultRequestCulture = new RequestCulture(Fallback, Fallback),
            SupportedCultures = new List<CultureInfo> { new(Fallback) },
            SupportedUICultures = cultures,
            FallBackToParentUICultures = true,
        };
        o.RequestCultureProviders.Clear();
        o.RequestCultureProviders.Add(new ChoiceProvider());
        o.RequestCultureProviders.Add(new UiOnlyProvider(new AcceptLanguageHeaderRequestCultureProvider { Options = o, MaximumAcceptLanguageHeaderValuesToTry = 5 }));
        return o;
    }

    private static ProviderCultureResult UiOnly(string ui) => new(new List<StringSegment> { new(Fallback) }, new List<StringSegment> { new(ui) });

    /// The viewer's cookie, then the installation default. "auto" in either falls through to Accept-Language.
    private sealed class ChoiceProvider : RequestCultureProvider
    {
        public override async Task<ProviderCultureResult?> DetermineProviderCultureResult(HttpContext httpContext)
        {
            var chosen = Choice(httpContext.Request.Cookies[Cookie]);
            if (chosen is not null) return chosen == Auto ? null : UiOnly(chosen);
            var def = httpContext.RequestServices.GetService(typeof(NumberFormatDefault)) is NumberFormatDefault d
                ? await d.ReadAsync(httpContext.RequestAborted).ConfigureAwait(false) : Auto;
            return def == Auto ? null : UiOnly(def);
        }
    }

    /// The Accept-Language choice as the UI culture only; the parsing culture stays the fallback.
    private sealed class UiOnlyProvider(IRequestCultureProvider inner) : RequestCultureProvider
    {
        public override async Task<ProviderCultureResult?> DetermineProviderCultureResult(HttpContext httpContext)
        {
            var r = await inner.DetermineProviderCultureResult(httpContext).ConfigureAwait(false);
            if (r is null || r.UICultures.Count == 0) return null;
            return new ProviderCultureResult(new List<StringSegment> { new(Fallback) }, r.UICultures);
        }
    }
}

/// <summary>
/// Reads the installation default (<see cref="DisplayCulture.Setting"/>) with a one-minute cache. Fails OPEN to "auto":
/// a settings read that fails must never stop a page from rendering.
/// </summary>
public sealed class NumberFormatDefault(ISettingsStoreReader reader, IMemoryCache cache, ILogger<NumberFormatDefault> log)
{
    private const string Key = "si-number-format-default";

    public async Task<string> ReadAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(Key, out string? hit) && hit is not null) return hit;
        var value = DisplayCulture.Auto;
        try
        {
            var row = (await reader.ReadSettingsAsync(ct).ConfigureAwait(false)).Rows
                .FirstOrDefault(r => r.Scope == CatalogSetting.WebScope && r.Name.Equals(DisplayCulture.Setting, StringComparison.OrdinalIgnoreCase));
            if (row?.ValueJson is { } j)
            {
                using var d = JsonDocument.Parse(j);
                if (d.RootElement.ValueKind == JsonValueKind.String) value = DisplayCulture.Choice(d.RootElement.GetString()) ?? DisplayCulture.Auto;
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            log.LogDebug(ex, "number format default could not be read -- automatic");
        }
        cache.Set(Key, value, TimeSpan.FromMinutes(1));
        return value;
    }
}
