#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  SMTP delivery: the anonymous and authenticated send paths.
#
#  The two transports the mail step chooses between. Separated so a change to delivery cannot be
#  confused with a change to what is being delivered.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Test-SIMailAttachmentFits {
    <#
        Will this file fit inside the relay's message-size limit once it is attached?

        🔑 THE ANSWER IS NOT THE FILE SIZE. MIME attachments are base64-encoded, which inflates them
        by ~37%, so a 10 MB workbook is ~13.7 MB of message. A check against the on-disk size passes
        and the relay still rejects -- and an oversized attachment does not arrive truncated, it takes
        the WHOLE MESSAGE with it. The operator then loses the AI summary and the findings as well as
        the spreadsheet, which is the opposite of the intended trade.

        Pure and parameterised so the boundary is provable without a mail server or a 250 MB file.
        Returns the numbers as well as the verdict, because the caller has to tell the operator what
        was too big and by how much.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][long]$SizeBytes,
        [Parameter()][double]$MaxMb = 24
    )
    $encodedMb = [Math]::Round(($SizeBytes * 1.37) / 1MB, 1)
    [pscustomobject]@{
        DiskMb    = [Math]::Round($SizeBytes / 1MB, 1)
        EncodedMb = $encodedMb
        MaxMb     = $MaxMb
        Fits      = ($encodedMb -le $MaxMb)
    }
}

function Send-MailAnonymous {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SmtpServer,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter()] [bool]$UseSsl = $false,

        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,

        [Parameter()] [string[]]$Attachments,
        [Parameter()] [ValidateSet('Normal','High','Low')] [string]$Priority = 'High'
    )

    # v2.2.247 -- diagnostic-rich anonymous send. NEVER throws (operator: "no
    # -stop as script must continue"). Returns $true on success, $false on
    # failure, with the relay's actual status code / .NET exception chain
    # printed inline so the operator can see WHY mail didn't arrive instead
    # of a green "[OK] anonymous mail sent" line that lied about success.
    #
    # Two phases:
    #   1. TCP pre-flight (5s, async with timeout). If we can't even open a
    #      socket -- DNS failure, firewall ACL, listener down, source-IP
    #      restriction -- skip the cmdlet call entirely and log the cause.
    #   2. Send-MailMessage with -ErrorAction SilentlyContinue + -ErrorVariable.
    #      Any non-terminating error from the cmdlet now lands in $smtpErr
    #      instead of getting swallowed; we walk the .NET exception chain
    #      (SmtpException -> SmtpStatusCode, InnerException) and print each
    #      level. Then return $false so the caller knows not to log [OK].

    Write-Output ("Sending mail (anonymous) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)

    # 1. TCP pre-flight
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($SmtpServer, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(5000, $false)) {
            $tcp.Close()
            Write-Output ("   TCP pre-flight FAILED (5s timeout) -- {0}:{1}" -f $SmtpServer, $Port)
            Write-Output  "   (likely cause: DNS resolution slow / wrong, firewall ACL silently dropping, listener not on this port)"
            return $false
        }
        $tcp.EndConnect($iar)
        $tcp.Close()
        Write-Output ("   TCP pre-flight OK -- {0}:{1} accepted connection" -f $SmtpServer, $Port)
    } catch {
        Write-Output ("   TCP pre-flight FAILED -- {0}:{1} :: {2}" -f $SmtpServer, $Port, $_.Exception.Message)
        Write-Output  "   (likely cause: DNS resolution, firewall ACL, listener down, or relay restricting source IP)"
        return $false
    }

    $params = @{
        SmtpServer  = $SmtpServer
        Port        = $Port
        From        = $From
        To          = $To
        Subject     = $Subject
        Body        = $BodyHtml
        BodyAsHtml  = $true
        Encoding    = 'UTF8'
        Priority    = $Priority
        ErrorAction = 'SilentlyContinue'
    }
    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    # 2. Send; capture any non-terminating error so we can surface details
    $smtpErr = $null
    Send-MailMessage @params -ErrorVariable smtpErr 2>$null

    if ($smtpErr -and $smtpErr.Count -gt 0) {
        Write-Output  "   SMTP send FAILED -- relay rejected or cmdlet hit a non-terminating error:"
        foreach ($er in $smtpErr) {
            $ex = $er.Exception
            if ($null -eq $ex) { continue }
            Write-Output ("   Exception type : {0}" -f $ex.GetType().FullName)
            Write-Output ("   Message        : {0}" -f $ex.Message)
            if ($ex.PSObject.Properties['StatusCode']) {
                Write-Output ("   SMTP StatusCode: {0}" -f $ex.StatusCode)
            }
            $inner = $ex.InnerException
            $depth = 0
            while ($inner -and $depth -lt 5) {
                Write-Output ("   InnerException : [{0}] {1}" -f $inner.GetType().FullName, $inner.Message)
                if ($inner.PSObject.Properties['StatusCode']) {
                    Write-Output ("   Inner StatusCode: {0}" -f $inner.StatusCode)
                }
                $inner = $inner.InnerException
                $depth++
            }
        }
        Write-Output  "   (common causes: relay requires AUTH, sender not whitelisted, RBL block, SPF/DMARC reject, TLS handshake mismatch)"
        return $false
    }

    return $true
}

function Send-MailSecure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$SmtpServer,
        [Parameter(Mandatory)] [int]$Port,
        [Parameter()] [bool]$UseSsl = $false,

        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string]$From,
        [Parameter(Mandatory)] [string[]]$To,
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$BodyHtml,

        [Parameter()] [string[]]$Attachments,
        [Parameter()] [ValidateSet('Normal','High','Low')] [string]$Priority = 'High'
    )

    $params = @{
        SmtpServer  = $SmtpServer
        Port        = $Port
        Credential  = $Credential
        From        = $From
        To          = $To
        Subject     = $Subject
        Body        = $BodyHtml
        BodyAsHtml  = $true
        Encoding    = 'UTF8'
        Priority    = $Priority
    }

    if ($UseSsl) { $params.UseSsl = $true }
    if ($Attachments -and $Attachments.Count -gt 0) { $params.Attachments = $Attachments }

    Write-Output ("Sending mail (secure) to {0} with subject '{1}'" -f ($To -join ', '), $Subject)
    Send-MailMessage @params
}
