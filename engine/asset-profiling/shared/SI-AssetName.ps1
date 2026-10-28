#Requires -Version 5.1
<#
    SI v3 -- THE SYNTHETIC ASSET NAME. One rule, one place, four engines.

    🔒 THE CONTRACT SI_AssetName MAKES: it is NEVER blank. When no source anywhere holds a name for an
    asset, this produces a marked stand-in rather than a blank or a bare identifier.

    🔴 WHY NOT JUST USE THE ID -- the question this file exists to answer. Falling back to the raw
    identifier satisfies "never blank" and looks like data. MEASURED 2026-08-27: 78 of 198 endpoint rows
    already carried a 40-hex MDE machine id in AssetName, and it reached the customer's Excel looking
    exactly like a hostname that happened to be unreadable. A marked value says the true thing instead:
    NOTHING KNOWS THIS ASSET'S NAME. Same stability, same uniqueness, no false impression.

    🔑 PROPERTIES THAT MATTER, and each one is asserted by a test:
      * DETERMINISTIC -- derived only from the id. No clock, no random, no run id. The same asset gets
        the same synthetic name on every run, forever, which is what makes it safe to show in a report
        and safe to group by.
      * UNIQUE -- the id is unique per asset, so the name is too. Reports that group or count by name
        stay correct; a shared placeholder would silently merge distinct assets into one row, which is
        this codebase's oldest scar (a blank join key manufacturing 296 findings, v2.2.442).
      * RECOGNISABLE -- the 'unnamed-' prefix is a contract a consumer can test without parsing.
      * HARMLESS TO CMDB MATCHING -- it will never match a real CI, which is CORRECT: these assets have
        no name to match on. A raw hash never matched either, so nothing regresses.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

function Get-SISyntheticAssetName {
    <#
        -Engine  'endpoint' | 'azure' | 'identity' | 'publicip'
        -Id      the asset's stable identifier (PrimaryEntityId)

        Returns 'unnamed-<engine>-<8 chars of the id>', or $null when there is no id at all -- because
        with no id there is nothing stable to build from, and inventing one would be worse than a blank.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Engine,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Id
    )

    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }

    $eng = ([string]$Engine).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($eng)) { $eng = 'asset' }

    # 🪤 Strip to alphanumerics BEFORE truncating. Ids in this estate include ARM paths
    # (/subscriptions/.../virtualMachines/x) and IP addresses -- taking the first 8 characters raw would
    # yield '/subscri' for every Azure resource on earth, which is a shared placeholder wearing a unique
    # name. Stripping first means the 8 characters carry actual entropy.
    $clean = ($Id -replace '[^A-Za-z0-9]', '')
    if ([string]::IsNullOrWhiteSpace($clean)) {
        # An id made entirely of punctuation is not something to guess at.
        return $null
    }

    # 🪤 And take the TAIL, not the head. An ARM resource id's entropy is at the end (the resource name);
    # its first characters are the subscription guid, shared by every resource in the subscription.
    $take = [Math]::Min(8, $clean.Length)
    $frag = $clean.Substring($clean.Length - $take, $take).ToLowerInvariant()

    return ('unnamed-{0}-{1}' -f $eng, $frag)
}

function Test-SISyntheticAssetName {
    <# Is this value one of ours? A contract a consumer can test without parsing the shape. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    return ($Value -like 'unnamed-*')
}
