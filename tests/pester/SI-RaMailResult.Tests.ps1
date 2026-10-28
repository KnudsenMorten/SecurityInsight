#Requires -Version 5.1
<#
    Risk Analysis never says "mail sent" after the relay refused it (found 2026-10-03).
    Send-MailAnonymous writes its diagnostic lines to the output stream AND returns [bool], so a plain assignment
    collected strings + $false (always truthy). Send-MailSecure called Send-MailMessage without -ErrorAction Stop, so a
    refusal was a non-terminating error and the caller printed "secure mail sent".
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Mail.ps1')
}

Describe 'the mail result is the truth' {
    It 'a function that prints lines and returns $false yields FALSE through the RA read (executed)' {
        function script:Fake-Send { Write-Output 'Sending mail ...'; Write-Output '   SMTP send FAILED'; return $false }
        $ok = $false; foreach ($o in @(Fake-Send)) { if ($o -is [bool]) { $ok = $o } }
        $ok | Should -BeFalse
        $plain = Fake-Send
        [bool]$plain | Should -BeTrue -Because 'this is exactly the bug the RA read now avoids'
    }
    It 'RA reads the mail result from the one transport, which takes the last bool, not the whole output' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $c | Should -Not -Match '\$mailOk = Send-MailAnonymous'
        # MAIL-1: RA sends through the one transport and reads its verdict (Send-SIMail reads the LAST bool of Send-MailAnonymous)
        $c | Should -Match '\$__mailRes = Send-SIMail -Settings'
        $c | Should -Match 'if \(\$__mailRes\.Sent\)'
        (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-MailTransport.ps1')) | Should -Match '\$verdict = @\(\$out \| Where-Object \{ \$_ -is \[bool\] \}\) \| Select-Object -Last 1'
    }
    It 'Send-MailSecure turns a refused mail into an error (executed with Send-MailMessage faked)' {
        function script:Send-MailMessage { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments)]$Rest) Write-Error 'relay refused: 550 sender not allowed' }
        $cred = New-Object System.Management.Automation.PSCredential('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
        { Send-MailSecure -SmtpServer 'relay.example' -Port 587 -UseSsl $true -Credential $cred -From 'a@example.com' -To @('b@example.com') -Subject 's' -BodyHtml '<p>x</p>' 6>$null | Out-Null } |
            Should -Throw '*550*'
    }
}
