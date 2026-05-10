function Send-PlatformAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Context,

        [Parameter(Mandatory)]
        [string]$Subject,

        [string]$Message,

        [ValidateSet('Info','Warn','Error','Critical')]
        [string]$Severity = 'Warn',

        [string[]]$To,

        [string]$TeamsWebhookUrl,

        [string[]]$Attachments,

        [ValidateSet('Text','Html')]
        [string]$BodyFormat = 'Text',

        [ValidateSet('All','Teams','SMTP')]
        [string]$Channels = 'All',

        [switch]$Anonymous
    )

    $sent = @()
    $scriptName = if ($MyInvocation.ScriptName) { Split-Path -Leaf $MyInvocation.ScriptName } else { 'unknown' }

    # ------------------- Teams -------------------
    if ($Channels -in @('All','Teams')) {
        if (-not $TeamsWebhookUrl -and $Context.Tenant.TeamsWebhookSecret) {
            try {
                $TeamsWebhookUrl = Get-PlatformSecret -Context $Context -Name $Context.Tenant.TeamsWebhookSecret -AsPlainText
            }
            catch {
                Write-Warning "Send-PlatformAlert: Teams webhook secret '$($Context.Tenant.TeamsWebhookSecret)' unavailable: $($_.Exception.Message)"
            }
        }

        if ($TeamsWebhookUrl) {
            $color = switch ($Severity) {
                'Info'     { '0078D4' }
                'Warn'     { 'F2C811' }
                'Error'    { 'D13438' }
                'Critical' { '8B0000' }
            }
            $teamsText = if ($BodyFormat -eq 'Html') { $Message } else { $Message -replace "`r?`n",'<br>' }
            $payload = @{
                '@type'    = 'MessageCard'
                '@context' = 'http://schema.org/extensions'
                themeColor = $color
                summary    = $Subject
                title      = "[$Severity] $Subject"
                text       = $teamsText
                sections   = @(@{
                    facts = @(
                        @{ name = 'Script';        value = $scriptName }
                        @{ name = 'Host';          value = $Context.Host.Kind }
                        @{ name = 'Computer';      value = $Context.Host.ComputerName }
                        @{ name = 'CorrelationId'; value = $Context.CorrelationId }
                        @{ name = 'UTC';           value = [datetime]::UtcNow.ToString('o') }
                    )
                })
            } | ConvertTo-Json -Depth 10 -Compress

            try {
                Invoke-RestMethod -Method POST -Uri $TeamsWebhookUrl -Body $payload -ContentType 'application/json' -ErrorAction Stop | Out-Null
                $sent += 'Teams'
            }
            catch {
                Write-Warning "Send-PlatformAlert: Teams webhook POST failed: $($_.Exception.Message)"
            }
        }
    }

    # ------------------- SMTP -------------------
    if ($Channels -in @('All','SMTP') -and $To -and $Context.Tenant.SmtpServer -and $Context.Tenant.SmtpFrom) {
        $useAnon = $Anonymous -or (-not $Context.Identity.Legacy.SMTP)

        $smtpParams = @{
            SmtpServer  = $Context.Tenant.SmtpServer
            From        = $Context.Tenant.SmtpFrom
            To          = $To
            Subject     = "[$Severity] $Subject"
            Body        = $Message
            UseSsl      = $true
            ErrorAction = 'Stop'
        }
        if ($BodyFormat -eq 'Html') { $smtpParams.BodyAsHtml = $true }
        if ($Attachments)           { $smtpParams.Attachments = $Attachments }
        if (-not $useAnon)          { $smtpParams.Credential  = $Context.Identity.Legacy.SMTP }

        try {
            Send-MailMessage @smtpParams
            $sent += if ($useAnon) { 'SMTP-Anonymous' } else { 'SMTP' }
        }
        catch {
            Write-Warning "Send-PlatformAlert: SMTP send failed: $($_.Exception.Message)"
        }
    }

    if (-not $sent) {
        Write-Warning "Send-PlatformAlert: no channel delivered (Channels=$Channels, TeamsConfigured=$([bool]$TeamsWebhookUrl -or [bool]$Context.Tenant.TeamsWebhookSecret), SmtpConfigured=$([bool]$Context.Tenant.SmtpServer -and [bool]$Context.Tenant.SmtpFrom -and [bool]$To))."
    }

    Write-PlatformLog -Context $Context -Severity $Severity -Event 'platform.alert' -Message $Subject -Data @{
        channels    = $sent
        to          = $To
        attachments = $Attachments
        format      = $BodyFormat
    }

    return $sent
}
