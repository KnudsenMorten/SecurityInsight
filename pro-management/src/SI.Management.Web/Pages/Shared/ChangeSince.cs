namespace SI.Management.Web.Pages;

/// Which way a measure is good: a count of findings and the average risk score per finding are better LOWER; the 0-100 risk score
/// (higher = safer) is better HIGHER.
public enum Better { Lower, Higher }

/// How a measure is shown: a count (whole), a score (whole, as every risk score in the app) or a percentage.
public enum ChangeKind { Count, Score, Percent }

/// <summary>
/// THE ONE "change since" of every tile (#636, owner 2026-10-19: a zero change showed as "(worse)" in red). The change is
/// judged on the value AS SHOWN: a difference that rounds to 0 on screen is "no change" (neutral), never a colour; a
/// change the other way is better (green) or worse (red) by the measure's own direction (<see cref="Better"/>).
/// Rendered by Pages/Shared/_ChangeSince.cshtml. Null <see cref="Then"/> = no earlier value: nothing is shown.
/// </summary>
public sealed record ChangeSince(double? Now, double? Then, Better Better, ChangeKind Kind, string? Since)
{
    /// The difference as the screen shows it (rounded the way the value is shown).
    public double? Shown => Now is { } n && Then is { } t ? Round(n) - Round(t) : null;

    private double Round(double v) => Kind == ChangeKind.Percent ? Math.Round(v, 1) : Math.Round(v, MidpointRounding.AwayFromZero);

    /// good | bad | neutral (no change) | none (nothing to compare with).
    public string Tone => Shown is not { } d ? "none" : d == 0 ? "neutral" : (d < 0) == (Better == Better.Lower) ? "good" : "bad";

    /// The word after the numbers: better / worse / no change.
    public string Meaning => Tone switch { "good" => "better", "bad" => "worse", "neutral" => "no change", _ => "" };

    /// "+3", "-1.234", or "no change".
    public string DeltaText => Shown is not { } d ? "" : d == 0 ? "no change"
        : Kind == ChangeKind.Percent ? Fmt.Signed(d, 1) + " pp"
        : Kind == ChangeKind.Score ? Fmt.SignedScore(d) : Fmt.Signed(d, 0);

    /// The whole line: "+3 since 2026-10-17 (worse)", "no change since 2026-10-17".
    public string Text => Shown is not { } d ? "" : d == 0
        ? "no change" + (Since is null ? "" : " since " + Since)
        : DeltaText + (Since is null ? "" : " since " + Since) + " (" + Meaning + ")";

    public static ChangeSince Of(double? now, double? then, Better better, ChangeKind kind = ChangeKind.Count, string? since = null) => new(now, then, better, kind, since);
}
