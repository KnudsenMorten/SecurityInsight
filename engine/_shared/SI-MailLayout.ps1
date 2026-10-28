#Requires -Version 5.1
<#
    SECURITYINSIGHT -- THE ONE MAIL LAYOUT (framework MAIL-2, REQUIREMENTS #573: "every SI mail must be readable, with
    real paragraphs and blank lines"). Every mail SecurityInsight sends goes through it: Send-SIMail (SI-MailTransport.ps1)
    calls Format-SIMailBody on EVERY body before it is sent, whoever built it -- the Risk Analysis report, the guard
    mails, the close-loop / exemption / governance / department / task-digest mails, the licence notice, and the mails
    the web app queues in its outboxes (cfg.SignInMail, cfg.ExemptionMail, cfg.GovernanceMail, cfg.ReportMail).
    tests\pester\SIv3-MailReadable.Tests.ps1 renders each mail type and fails when paragraphs or blank lines are lost,
    and fails when a sender bypasses Format-SIMailBody.

    WHY THE MAILS WERE HARD TO READ (the root causes this file removes):
      1. plain text (or multi-line free text: a reason, a comment, an AI narrative) put into HTML without turning its
         line breaks into paragraphs / <br> -- HTML collapses "\n" and "\n\n" into one space, so paragraphs ran together;
      2. a <p> per LINE (the AI narrative) instead of a <p> per paragraph, with a 6 px gap -- no visible blank line;
      3. <p> with no margin of its own -- Outlook (desktop, web) drops the default paragraph spacing, so paragraphs had no
         blank line between them;
      4. text joined with "`n" (LF only) for the text variant -- no CRLF, no blank line between paragraphs.

    THE BODY: one HTML body. Microsoft Graph sendMail (the shared-mailbox mode) takes ONE body (contentType HTML or Text)
    -- it has no multipart/alternative -- and the SMTP mode's Send-MailMessage also takes one body. So every mail is an
    HTML body built with real structure: a <p> per paragraph (explicit margin), <br> only inside a paragraph, <ul> for
    lists, headings, every interpolated value HTML-encoded. The plain-text rendering of the same mail
    (ConvertTo-SIMailText: CRLF line ends, a blank line between paragraphs) is returned by Send-SIMail (.Text) and is what
    a multipart sender would put in its text/plain part.

    NO TABLES (REQUIREMENTS #728, owner: "Drop the tables in emails as it becomes hard to read on mobiles / Make line with
    topic: / Then text. / Use bold where it can add important context / Use line spacing where needed"). The layout of
    every SI mail, the same as Invardia's owner notes:
      - a SUMMARY block first (data-mail-summary): 2-4 short lines -- what happened, the numbers, whether the reader must act;
      - SECTIONS with a heading (ConvertTo-SIMailHeadingHtml);
      - "Topic: text" lines, the topic in bold and short (ConvertTo-SIMailLineHtml / ConvertTo-SIMailFactsHtml);
      - ONE LINE PER RECORD instead of a table row ("Device_Missing_CVEs_Detailed: Complete, 1,060,000 rows");
      - bullets for lists; blank space between the parts;
      - no fixed widths: the frame is a <div> with a max-width, so a phone shows it at its own width.
    No helper here emits <table>, and tests\pester\SIv3-MailNoTables.Tests.ps1 fails when any SI mail does.

    PURE functions only. PowerShell 5.1 and 7 syntax; no modules.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SIMailLayout = @{
    Font      = 'font-family:Segoe UI,Arial,sans-serif;'
    Ink       = '#0B1633'
    Muted     = '#52607D'
    Blue      = '#1B4FE4'
    Line      = '#DCE3F2'
    Panel     = '#F6F8FD'
    Tint      = '#EEF3FE'
    # an explicit bottom margin on every paragraph: Outlook drops the default <p> spacing
    PStyle    = 'margin:0 0 14px 0;line-height:1.55;'
    Marker    = 'data-si-mail-layout'
    # the elements that make a body HTML (Format-SIMailBody); anything else tag-like in a text is text
    HtmlElement = '(?i)<!DOCTYPE\b|</?(html|body|head|p|div|span|table|thead|tbody|tr|td|th|br|hr|h[1-6]|ul|ol|li|strong|b|em|i|u|a|img|code|pre|blockquote|font|center|small|meta|style)(\s[^>]*)?/?>'
}

function ConvertTo-SIMailEncoded {
    <# PURE. HTML-encode one value (never raw text in HTML). #>
    param([AllowNull()]$Value)
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-SIMailLinkified {
    <# PURE. Encoded text with every https:// link clickable. #>
    param([AllowEmptyString()][string]$Text)
    if (-not $Text) { return '' }
    $sb = New-Object System.Text.StringBuilder
    $i = 0
    foreach ($m in [regex]::Matches($Text, 'https://[^\s<>"'']+')) {
        $url = $m.Value
        while ($url.Length -gt 8 -and '.,;:)]'.Contains([string]$url[$url.Length - 1])) { $url = $url.Substring(0, $url.Length - 1) }
        [void]$sb.Append((ConvertTo-SIMailEncoded $Text.Substring($i, $m.Index - $i)))
        $u = ConvertTo-SIMailEncoded $url
        [void]$sb.Append(('<a href="{0}" style="color:{1};text-decoration:underline;">{0}</a>' -f $u, $script:SIMailLayout.Blue))
        $i = $m.Index + $url.Length
    }
    if ($i -lt $Text.Length) { [void]$sb.Append((ConvertTo-SIMailEncoded $Text.Substring($i))) }
    $sb.ToString()
}

function ConvertTo-SIMailInlineHtml {
    <# PURE. One free-text VALUE (a reason, a comment, a detail) for inside a paragraph or a table cell: encoded, links
       clickable, every line break kept as <br> (a blank line as two). #>
    param([AllowNull()]$Text)
    $t = ([string]$Text) -replace "`r`n", "`n" -replace "`r", "`n"
    $t = $t.Trim()
    if (-not $t) { return '' }
    ((@($t -split "`n") | ForEach-Object { ConvertTo-SIMailLinkified $_.TrimEnd() }) -join '<br>')
}

function ConvertTo-SIMailParagraphHtml {
    <#
        PURE. Plain text -> HTML blocks: a blank line separates paragraphs (<p>, with the explicit margin), a single line
        break stays a <br> inside its paragraph, a run of lines starting with "- " / "* " is a <ul>. Every value is
        encoded. -Markdown adds the subset an AI narrative uses: "## " / "### " headings, **bold**, _italic_ and
        [text](https://link).
    #>
    param([AllowNull()]$Text, [switch]$Markdown, [string]$Style)
    $L = $script:SIMailLayout
    $pStyle = if ($Style) { $Style } else { $L.PStyle }
    $t = ([string]$Text) -replace "`r`n", "`n" -replace "`r", "`n"
    if (-not $t.Trim()) { return '' }
    $inline = {
        param([string]$s)
        if (-not $Markdown) { return (ConvertTo-SIMailLinkified $s) }
        # markdown links first, the rest encoded + linkified
        $out = New-Object System.Text.StringBuilder; $i = 0
        foreach ($m in [regex]::Matches($s, '\[([^\]\n]+)\]\((https?://[^\s)]+)\)')) {
            [void]$out.Append((ConvertTo-SIMailLinkified $s.Substring($i, $m.Index - $i)))
            [void]$out.Append(('<a href="{0}" style="color:{1};text-decoration:underline;">{2}</a>' -f (ConvertTo-SIMailEncoded $m.Groups[2].Value), $L.Blue, (ConvertTo-SIMailEncoded $m.Groups[1].Value)))
            $i = $m.Index + $m.Length
        }
        if ($i -lt $s.Length) { [void]$out.Append((ConvertTo-SIMailLinkified $s.Substring($i))) }
        $h = $out.ToString()
        $h = [regex]::Replace($h, '\*\*([^\*\n]+?)\*\*', '<strong>$1</strong>')
        $h = [regex]::Replace($h, '(^|\s)_([^_\n]+?)_(\s|[\.,;:\)\]]|$)', '$1<em>$2</em>$3')
        $h
    }
    $blocks = New-Object System.Collections.Generic.List[string]
    foreach ($para in [regex]::Split($t.Trim(), '\n[ \t]*\n')) {
        $lines = @($para -split "`n" | ForEach-Object { $_.TrimEnd() } | Where-Object { $_.Trim() })
        if (-not $lines.Count) { continue }
        $buf = New-Object System.Collections.Generic.List[string]
        $ul = New-Object System.Collections.Generic.List[string]
        $flushP = { if ($buf.Count) { $blocks.Add(('<p style="{0}{1}">{2}</p>' -f $L.Font, $pStyle, ($buf -join '<br>'))); $buf.Clear() } }
        $flushU = { if ($ul.Count) { $blocks.Add(('<ul style="{0}margin:0 0 14px 0;padding:0 0 0 22px;">{1}</ul>' -f $L.Font, (($ul | ForEach-Object { '<li style="margin:0 0 4px 0;">' + $_ + '</li>' }) -join ''))); $ul.Clear() } }
        foreach ($ln in $lines) {
            if ($Markdown -and $ln -match '^\s*(#{2,3})\s+(.+)$') {
                & $flushP; & $flushU
                $size = if ($matches[1].Length -eq 2) { '16px' } else { '14px' }
                $blocks.Add(('<h3 style="{0}font-size:{1};color:{2};margin:18px 0 8px 0;">{3}</h3>' -f $L.Font, $size, $L.Ink, (& $inline $matches[2].Trim())))
                continue
            }
            if ($ln -match '^\s*[-*•]\s+(.+)$') { & $flushP; $ul.Add((& $inline $matches[1].Trim())); continue }
            & $flushU
            $buf.Add((& $inline $ln.Trim()))
        }
        & $flushP; & $flushU
    }
    ($blocks -join "`r`n")
}

function ConvertTo-SIMailHeadingHtml {
    <# PURE. A section heading (#728: sections with a heading). Encoded. #>
    param([AllowEmptyString()][string]$Text)
    if (-not "$Text".Trim()) { return '' }
    $L = $script:SIMailLayout
    ('<h2 style="{0}font-size:16px;line-height:1.35;font-weight:700;color:{1};margin:24px 0 10px 0;">{2}</h2>' -f $L.Font, $L.Ink, (ConvertTo-SIMailEncoded $Text))
}

function ConvertTo-SIMailLineHtml {
    <#
        PURE. ONE "Topic: text" line (#728): the topic in bold, then the text, as a paragraph of its own (blank space after
        it). -Text is plain text (encoded, links clickable, line breaks kept); -Html is a trusted fragment already built with
        encoded values (a link, a bold number). No topic = the text alone.
    #>
    param([AllowEmptyString()][string]$Topic, [AllowNull()]$Text, [string]$Html, [string]$Color)
    $L = $script:SIMailLayout
    $body = if ($PSBoundParameters.ContainsKey('Html')) { $Html } else { ConvertTo-SIMailInlineHtml $Text }
    $t = "$Topic".Trim()
    if (-not $t -and -not "$body".Trim()) { return '' }
    $lead = if ($t) { '<strong>' + (ConvertTo-SIMailEncoded ($t.TrimEnd(':'))) + ':</strong> ' } else { '' }
    $ink = if ($Color) { $Color } else { $L.Ink }
    ('<p style="{0}font-size:14px;line-height:1.5;color:{1};margin:0 0 10px 0;">{2}{3}</p>' -f $L.Font, $ink, $lead, $body)
}

function ConvertTo-SIMailFactsHtml {
    <#
        PURE. Key / value facts as "Topic: text" lines (#728: no table), one line per fact, the topic in bold; empty values
        left out. -Facts: an ordered dictionary, or pairs @(@(k,v), ...). -Title: a section heading above them.
    #>
    param($Facts, [string]$Title)
    $L = $script:SIMailLayout
    $rows = New-Object System.Collections.Generic.List[object]
    if ($Facts -is [System.Collections.IDictionary]) { foreach ($k in $Facts.Keys) { $rows.Add(@([string]$k, $Facts[$k])) } }
    else { foreach ($p in @($Facts)) { if ($null -ne $p) { $rows.Add(@([string]@($p)[0], @($p)[1])) } } }
    $kept = @($rows | Where-Object { "$(@($_)[1])".Trim() })
    if (-not $kept.Count) { return '' }
    $sb = New-Object System.Text.StringBuilder
    if ($Title) { [void]$sb.Append((ConvertTo-SIMailHeadingHtml $Title)) }
    [void]$sb.Append(('<div style="{0}margin:0 0 16px 0;" data-mail-facts>' -f $L.Font))
    foreach ($r in $kept) { [void]$sb.Append((ConvertTo-SIMailLineHtml -Topic @($r)[0] -Text @($r)[1])) }
    [void]$sb.Append('</div>')
    $sb.ToString()
}

function ConvertTo-SIMailSummaryHtml {
    <#
        PURE. The SUMMARY block every mail starts with (#728): 2-4 short lines -- what happened, the numbers, whether the
        reader must act. -Lines: plain text (encoded), one per line; -Html: trusted fragments (already encoded) instead.
        A tinted block with a blue edge, no table, no fixed width (data-mail-summary: the portal link line goes under it).
    #>
    param([AllowEmptyCollection()][string[]]$Lines = @(), [AllowEmptyCollection()][string[]]$Html = @())
    $L = $script:SIMailLayout
    $parts = @(@($Html | Where-Object { "$_".Trim() }) + @($Lines | Where-Object { "$_".Trim() } | ForEach-Object { ConvertTo-SIMailInlineHtml $_ }))
    if (-not $parts.Count) { return '' }
    ('<div data-mail-summary style="{0}background:{1};border-left:4px solid {2};border-radius:4px;padding:12px 16px;margin:0 0 18px 0;font-size:15px;line-height:1.55;color:{3};"><p style="margin:0;">{4}</p></div>' -f `
        $L.Font, $L.Tint, $L.Blue, $L.Ink, ($parts -join '<br>'))
}

function ConvertTo-SIMailButtonHtml {
    <# PURE. The one blue button: a styled link in a paragraph of its own (no table, #728). Not https:// = no button. #>
    param([string]$Url, [string]$Text)
    if ("$Url" -notmatch '^https://') { return '' }
    $L = $script:SIMailLayout
    ('<p data-mail-button style="{2}margin:8px 0 18px 0;line-height:1.2;"><a href="{1}" target="_blank" style="{2}display:inline-block;background:{0};border:2px solid {0};border-radius:8px;padding:12px 24px;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none;">{3}</a></p>' -f `
        $L.Blue, (ConvertTo-SIMailEncoded $Url), $L.Font, (ConvertTo-SIMailEncoded $Text))
}

function New-SIMailFrameHtml {
    <#
        PURE. The frame every SI mail sits in (#728: no table, no fixed width -- a <div> with a max-width, so a phone shows it
        at its own width): the SecurityInsight bar (an optional -Subtitle line under it: the tenant, the time), the title,
        the -ContentHtml (trusted, already built with encoded values), the footer line. Carries the layout marker.
    #>
    param([string]$Title, [Parameter(Mandatory)][AllowEmptyString()][string]$ContentHtml, [string]$Footer, [string]$FooterHtml,
          [string]$Brand = 'SecurityInsight', [string]$Subtitle)
    $L = $script:SIMailLayout
    $foot = if ($FooterHtml) { $FooterHtml } elseif ($Footer) { ConvertTo-SIMailInlineHtml $Footer } else { '' }
    '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light only"></head>' +
        ('<body style="margin:0;padding:0;background:#f3f5f8;" {0}="1"><div style="background:#f3f5f8;padding:16px 8px;">' -f $L.Marker) +
        '<div style="max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #e0e6ed;border-radius:8px;">' +
        ('<div style="background:{0};padding:14px 20px;border-radius:8px 8px 0 0;{1}font-size:18px;font-weight:700;color:#ffffff;">{2}{3}</div>' -f $L.Ink, $L.Font, (ConvertTo-SIMailEncoded $Brand),
            $(if ($Subtitle) { '<br><span style="font-size:12px;font-weight:400;color:#cfdce8;">' + (ConvertTo-SIMailEncoded $Subtitle) + '</span>' } else { '' })) +
        $(if ($Title) { '<div style="padding:18px 20px 0 20px;"><h1 style="{0}font-size:21px;line-height:1.3;color:{1};margin:0 0 14px 0;">{2}</h1></div>' -f $L.Font, $L.Ink, (ConvertTo-SIMailEncoded $Title) } else { '' }) +
        ('<div style="padding:4px 20px 12px 20px;{0}font-size:14px;color:{1};">{2}</div>' -f $L.Font, $L.Ink, $ContentHtml) +
        $(if ($foot) { '<div style="padding:12px 20px 16px 20px;border-top:1px solid #e0e6ed;{0}font-size:11px;line-height:1.5;color:{1};">{2}</div>' -f $L.Font, $L.Muted, $foot } else { '' }) +
        '</div></div></body></html>'
}

function New-SIMailLayout {
    <#
        PURE. A whole mail in the MAIL-2 / #728 layout, from PLAIN TEXT parts (everything is encoded here): the title, the
        summary first (a tinted block), the facts as "Topic: text" lines, the paragraphs (-Paragraphs: one string per paragraph, or one text with blank
        lines; lines starting "- " become a list), an optional trusted -BodyHtml fragment (already built with encoded
        values), the blue button to the exact page, the doc link, the footer line.
        Returns @{ Html; Text } -- Text: CRLF line ends, a blank line between paragraphs.
    #>
    param([string]$Title, [string]$Summary, $Facts, [string]$FactsTitle, [AllowEmptyCollection()][string[]]$Paragraphs = @(),
          [string]$BodyHtml, [string]$ButtonUrl, [string]$ButtonText = 'Open SecurityInsight', [string]$DocUrl, [string]$DocText = 'Documentation',
          [string]$Footer)
    $L = $script:SIMailLayout
    $parts = New-Object System.Text.StringBuilder
    if ($Summary) { [void]$parts.Append((ConvertTo-SIMailSummaryHtml -Lines @($Summary))) }
    if ($null -ne $Facts) { [void]$parts.Append((ConvertTo-SIMailFactsHtml -Facts $Facts -Title $FactsTitle)) }
    $text = (@($Paragraphs) | Where-Object { "$_".Trim() }) -join "`n`n"
    if ($text) { [void]$parts.Append((ConvertTo-SIMailParagraphHtml -Text $text)) }
    if ($BodyHtml) { [void]$parts.Append($BodyHtml) }
    [void]$parts.Append((ConvertTo-SIMailButtonHtml -Url $ButtonUrl -Text $ButtonText))
    if ("$DocUrl" -match '^https://') {
        [void]$parts.Append(('<p style="{0}{1}font-size:13px;color:{2};">{3}: <a href="{4}" style="color:{5};">{4}</a></p>' -f $L.Font, $L.PStyle, $L.Muted, (ConvertTo-SIMailEncoded $DocText), (ConvertTo-SIMailEncoded $DocUrl), $L.Blue))
    }
    $html = New-SIMailFrameHtml -Title $Title -ContentHtml $parts.ToString() -Footer $Footer
    [pscustomobject]@{ Html = $html; Text = (ConvertTo-SIMailText -Html $html) }
}

function ConvertTo-SIMailText {
    <#
        PURE. The plain-text rendering of an HTML mail: CRLF line ends, one blank line between paragraphs / headings /
        tables / lists, a list item as "- ", a table row as its cells separated by " | ", links as "text (url)". It is what
        a text/plain part carries and what the tests read for "a blank line between paragraphs".
    #>
    param([AllowEmptyString()][string]$Html)
    if (-not $Html) { return '' }
    $h = [regex]::Replace($Html, '(?is)<(head|style|script)\b.*?</\1>', '')
    $h = [regex]::Replace($h, '(?is)<!--.*?-->', '')
    $h = $h -replace "[\r\n\t]+", ' '
    $h = [regex]::Replace($h, '(?is)<a\b[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>', {
        param($m)
        $label = [regex]::Replace($m.Groups[2].Value, '<[^>]+>', '').Trim()
        $url = [System.Net.WebUtility]::HtmlDecode($m.Groups[1].Value)
        if (-not $label -or [System.Net.WebUtility]::HtmlDecode($label) -eq $url) { $url } else { $label + ' (' + $url + ')' }
    })
    $h = [regex]::Replace($h, '(?i)<br\s*/?>', "`n")
    $h = [regex]::Replace($h, '(?i)<li\b[^>]*>', "`n- ")
    $h = [regex]::Replace($h, '(?i)</t[dh]>', ' | ')
    $h = [regex]::Replace($h, '(?i)</tr>', "`n")
    $h = [regex]::Replace($h, '(?i)</?(p|h[1-6]|ul|ol|table|div|pre|blockquote)\b[^>]*>', "`n`n")
    $h = [regex]::Replace($h, '<[^>]+>', '')
    $h = [System.Net.WebUtility]::HtmlDecode($h)
    $lines = foreach ($ln in ($h -split "`n")) {
        $x = ($ln -replace '[  ]+', ' ').Trim()
        $x = $x -replace '(\s*\|\s*)+$', ''
        $x = $x -replace '^(\|\s*)+', ''
        $x
    }
    # collapse: at most one blank line in a row, none at the ends
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($x in $lines) {
        if (-not $x) { if ($out.Count -and $out[$out.Count - 1] -ne '') { $out.Add('') }; continue }
        $out.Add($x)
    }
    while ($out.Count -and $out[$out.Count - 1] -eq '') { $out.RemoveAt($out.Count - 1) }
    ($out -join "`r`n")
}

function Format-SIMailBody {
    <#
        PURE. THE chokepoint every mail goes through (Send-SIMail calls it on every body). Returns @{ Html; Text }.
          plain text (no HTML tag)  -> the MAIL-2 layout around it, its paragraphs and line breaks kept (New-SIMailLayout)
          HTML                      -> structure kept; every <p> without a margin of its own gets the explicit paragraph
                                       margin (Outlook drops the default spacing); a raw line break INSIDE a paragraph's
                                       text (multi-line free text) becomes <br> (a blank line: a paragraph break)
        Idempotent: a body already formatted is returned as it is.
    #>
    param([AllowEmptyString()][string]$BodyHtml, [string]$Title = 'SecurityInsight')
    $L = $script:SIMailLayout
    if ($BodyHtml -match $L.Marker) { return [pscustomobject]@{ Html = $BodyHtml; Text = (ConvertTo-SIMailText -Html $BodyHtml) } }
    # HTML = it carries a mail markup element. A text that merely holds something tag-like ("<script>" in a reason, an
    # address in angle brackets) is TEXT: it gets the layout, encoded -- never passed through as HTML.
    if ($BodyHtml -notmatch $L.HtmlElement) {
        # a plain-text body: never put raw text into HTML
        return (New-SIMailLayout -Title $Title -Paragraphs @(([string]$BodyHtml).Trim()))
    }
    $html = $BodyHtml
    # raw line breaks inside a paragraph's text -> <br> (two -> a paragraph gap)
    $html = [regex]::Replace($html, '(?is)(<p\b[^>]*>)(.*?)(</p>)', {
        param($m)
        $inner = $m.Groups[2].Value
        $inner = [regex]::Replace($inner, '(?<=[^\s>])[ \t]*\r?\n[ \t]*\r?\n[ \t]*(?=[^\s<])', '<br><br>')
        $inner = [regex]::Replace($inner, '(?<=[^\s>])[ \t]*\r?\n[ \t]*(?=[^\s<])', '<br>')
        $m.Groups[1].Value + $inner + $m.Groups[3].Value
    })
    # every <p> carries an explicit margin
    $html = [regex]::Replace($html, '(?i)<p(\s[^>]*)?>', {
        param($m)
        $attrs = $m.Groups[1].Value
        if ($attrs -match '(?i)\bstyle\s*=\s*"([^"]*)"') {
            $st = $matches[1]
            if ($st -match '(?i)(^|;)\s*margin(-[a-z]+)?\s*:') { return $m.Value }   # its own margin (or margin-top ...) is kept
            $newSt = $st.TrimEnd(';', ' ') + $(if ($st.Trim()) { ';' } else { '' }) + $L.PStyle
            return ('<p' + ($attrs -replace '(?i)\bstyle\s*=\s*"[^"]*"', ('style="' + $newSt.Replace('$', '$$') + '"')) + '>')
        }
        '<p' + $attrs + ' style="' + $L.PStyle + '">'
    })
    # the marker: formatted once
    if ($html -match '(?i)<body\b') { $html = [regex]::Replace($html, '(?i)<body\b', ('<body ' + $L.Marker + '="1"'), 1) }
    else { $html = '<div ' + $L.Marker + '="1">' + $html + '</div>' }
    [pscustomobject]@{ Html = $html; Text = (ConvertTo-SIMailText -Html $html) }
}
