#Requires -Version 5.1
<#
    TEST SHIM (#1383): the identity reads of the privilege-holding groups now go through Graph $batch
    (Invoke-SIGraphBatchGet -> Invoke-SIGraphBatchWave). A suite that describes its directory by mocking Invoke-SIGraphPaged
    per URL keeps doing so with:
        Mock Invoke-SIGraphBatchWave { Invoke-SITestGraphBatchViaPaged -Bodies $Bodies }
    Each item of each $batch body is answered by Invoke-SIGraphPaged -RelativeUrl <the item's url, %20 decoded> -- one call
    per item, exactly as the single reads made. A throw answers the item with the status its message names (a transient
    status as 500: Invoke-SIGraphPaged has already retried it); no status in the message = 500.
#>

function Invoke-SITestGraphBatchViaPaged {
    param([string[]]$Bodies)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($b in @($Bodies)) {
        $req = $b | ConvertFrom-Json
        $resp = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($req.requests)) {
            $url = [uri]::UnescapeDataString([string]$r.url)
            try {
                $rows = @(Invoke-SIGraphPaged -RelativeUrl $url -Token 't')
                $resp.Add([pscustomobject]@{ id = [string]$r.id; status = 200; body = [pscustomobject]@{ value = $rows } })
            } catch {
                $m = [string]$_.Exception.Message
                $st = 500
                if ($m -match '\((\d{3})\)') { $st = [int]$Matches[1] } elseif ($m -match ':\s*(\d{3})\s') { $st = [int]$Matches[1] }
                if ($st -in 429, 502, 503, 504) { $st = 500 }
                $resp.Add([pscustomobject]@{ id = [string]$r.id; status = $st; body = [pscustomobject]@{ error = [pscustomobject]@{ code = 'TestError'; message = $m } } })
            }
        }
        $out.Add([pscustomobject]@{ Response = [pscustomobject]@{ responses = $resp.ToArray() }; Status = 200; RetryAfter = $null; Error = '' })
    }
    , $out.ToArray()
}
