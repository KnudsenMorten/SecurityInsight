// Export PDF (framework ENV-REPORT-1 / MAIL-2 item 3): every [data-print] button opens the browser's own print dialog on
// the page as it is, laid out by the print stylesheet (css/report.css: A4, no menu, page numbers) -- "Save as PDF" makes
// the file. No server-side renderer, nothing leaves the browser, no new window.
(function () {
    'use strict';
    document.querySelectorAll('[data-print]').forEach(function (b) {
        b.addEventListener('click', function () { window.print(); });
    });
})();
