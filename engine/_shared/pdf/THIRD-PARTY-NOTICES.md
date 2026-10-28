# Third-party components -- the SecurityInsight mail PDF

SecurityInsight builds the PDF it attaches to its mails with these .NET libraries. They are not part of this repository:
the container images download them at build time from nuget.org (`container/Install-SIPdfLibrary.ps1`), pinned by
version and SHA-512 in `SI.Pdf.packages.json`. Only their managed DLLs are used -- no native code, no executable.

| Component | Version | Licence | Verified |
|---|---|---|---|
| PDFsharp (`PDFsharp`) -- `PdfSharp.dll`, `PdfSharp.Shared.dll`, `PdfSharp.System.dll`, `PdfSharp.Charting.dll` | 6.2.4 | MIT | nuspec of 6.2.4: `<license type="expression">MIT</license>` |
| MigraDoc (`PDFsharp-MigraDoc`) -- `MigraDoc.DocumentObjectModel.dll`, `MigraDoc.Rendering.dll` | 6.2.4 | MIT | nuspec of 6.2.4: `<license type="expression">MIT</license>` |
| Microsoft.Extensions.Logging.Abstractions | 8.0.3 | MIT | nuspec of 8.0.3 |
| Microsoft.Extensions.DependencyInjection.Abstractions | 8.0.2 | MIT | nuspec of 8.0.2 |

PDFsharp and MigraDoc: Copyright (c) empira Software GmbH (https://www.pdfsharp.com).
Microsoft.Extensions.*: Copyright (c) .NET Foundation and Contributors.

QuestPDF is NOT used (its licence is not MIT for commercial use).

## MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
