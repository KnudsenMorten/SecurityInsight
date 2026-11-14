What's new (framework WHATS-NEW-1) - Invardia's SHARED pieces, copied into SecurityInsight UNCHANGED.

Source: the Invardia repository, tools/whatsnew/, commit 3d5f82c7088362ab655f76b800f3cb7e7c92a649
("WHATS-NEW-SITE: the ONE What's new renderer, schema, check, import, site page and approval-mail card").

This folder is the ONE place SecurityInsight keeps them:
  - whats-new.js + whats-new.css  the GUI renderer the web app serves (/lib/whatsnew/), themed only through --wn-*
                                  (wwwroot/css/whats-new-theme.css)
  - whats-new.d.ts                the renderer's types (not used by SecurityInsight, kept so the set stays whole)
  - whats-new.schema.json         the file format of whats-new/<version>.json and the 3a limits
  - ConvertTo-WhatsNewMarkdown.ps1  WHATSNEW.md for GitHub, and -Check = the release gate's conformance check
                                  (release/SI-WhatsNew.ps1 runs it)

NEVER edit a file here. A change SecurityInsight needs is proposed to Invardia; a new Invardia version is copied in whole
and the commit and hashes below are updated together. tests/pester/SIv3-WhatsNew.Tests.ps1 fails when a file differs
from these hashes (SHA-256 of the file with LF line ends):

46cf2954135f1a571b4b5a73793cc72ec09bcc66b44597f30000aa5c58919963  ConvertTo-WhatsNewMarkdown.ps1
808733191fc1a3846d9de1f8aa0367f365b9fd33fbcee30027a29e6738821be4  whats-new.css
e4586377d17af87fc1606eb47a7c52510db61736c9930b72a26cba9e541fd1cf  whats-new.d.ts
9887793b954a700897707511c2e249a32cfde802733f40dbbdb12e0140a91677  whats-new.js
c9154fa4e95fa6111fa330b166e45c8c77dd5d7e8e55dd12e1b6347cec9e8b69  whats-new.schema.json
