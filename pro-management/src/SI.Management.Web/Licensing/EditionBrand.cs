namespace SI.Management.Web.Licensing;

/// <summary>
/// THE EDITION'S LOGO (owner 2026-10-28: "include the community logos in their community version"). ONE web app, both
/// editions: the logo, the favicon / app tile and the product name a person sees follow the installation's licence, decided
/// at RUNTIME by the same check that switches the paid pages (<see cref="IProLicence"/>, deny by default -- no licence, an
/// unreadable record or a database that does not answer = the Community edition). A Pro licence recorded later turns the
/// Pro logo on within a minute, a removed one turns it back to Community.
/// The files are Invardia's brand packs, unchanged (never recoloured or redrawn): Pro under wwwroot/brand/, the Community
/// edition under wwwroot/brand/community/ (brand/products/securityinsight/community in Invardia's repository). Which variant
/// where: the REVERSED horizontal logo on the always-dark brand bar, the COLOUR horizontal logo on light pages (the sign-in
/// landing, printed reports), the shield icon + app tiles for the favicon (the shield is the Invardia mark of every edition).
/// </summary>
public sealed record EditionBrand(bool Pro, string Product, string HeaderLogo, string LightLogo, string LogoAlt,
    string FaviconSvg, string? FaviconIco, string? AppTile180, string? AppTile192)
{
    public const string ProProduct = "SecurityInsight Pro", CommunityProduct = "SecurityInsight Community";

    public static readonly EditionBrand ProBrand = new(true, ProProduct,
        "/brand/invardia-securityinsight-pro-horizontal-reversed.svg",
        "/brand/invardia-securityinsight-pro-horizontal-colour.svg",
        "Invardia SecurityInsight Pro",
        "/brand/invardia-icon.svg", null, null, null);

    public static readonly EditionBrand CommunityBrand = new(false, CommunityProduct,
        "/brand/community/invardia-securityinsight-community-horizontal-reversed.svg",
        "/brand/community/invardia-securityinsight-community-horizontal-colour.svg",
        "Invardia SecurityInsight Community",
        "/brand/community/invardia-icon.svg", "/brand/community/favicon.ico",
        "/brand/community/invardia-app-tile-180.png", "/brand/community/invardia-app-tile-192.png");

    /// PURE. The brand of an edition.
    public static EditionBrand For(bool pro) => pro ? ProBrand : CommunityBrand;

    /// The brand of THIS installation now: Pro only while the licence check says Pro; anything else -- including a check that
    /// throws -- is the Community edition (never a crash of the page that shows the logo).
    public static async Task<EditionBrand> CurrentAsync(IProLicence? licence, CancellationToken ct)
    {
        if (licence is null) return CommunityBrand;
        try { return For(await licence.IsProAsync(ct)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return CommunityBrand; }
    }

    /// The favicon / app tile links for a page head, as HTML (the paths are this file's constants, never user input).
    public string IconLinks()
    {
        var s = $"<link rel=\"icon\" href=\"{FaviconSvg}\" type=\"image/svg+xml\" data-edition-icon=\"{(Pro ? "pro" : "community")}\" />";
        if (FaviconIco is not null) s += $"\n    <link rel=\"alternate icon\" href=\"{FaviconIco}\" sizes=\"16x16 32x32 48x48\" />";
        if (AppTile180 is not null) s += $"\n    <link rel=\"apple-touch-icon\" href=\"{AppTile180}\" sizes=\"180x180\" />";
        if (AppTile192 is not null) s += $"\n    <link rel=\"icon\" href=\"{AppTile192}\" type=\"image/png\" sizes=\"192x192\" />";
        return s;
    }
}
