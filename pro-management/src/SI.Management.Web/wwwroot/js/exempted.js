// #264: a view's "Show exempted" / "Include exempted" tick is carried through every link and GET form inside the page's
// main content, so a drill-down shows the same population. The server builds the main links with the tick already
// (ExemptedTick.Carry); this covers every other in-page link. Links that leave the app, set the tick themselves or are
// the tick are left alone. Nothing is stored: the tick lives in the URL of this view only.
(function () {
    'use strict';
    var bar = document.querySelector('[data-exempted-bar]');
    if (!bar) return;
    var value = bar.getAttribute('data-exempted-carry');
    if (value !== '1' && value !== '0') return;
    var main = document.getElementById('main');
    if (!main) return;
    var key = 'exempted';
    function carry(href) {
        if (!href || href.charAt(0) !== '/' || href.charAt(1) === '/') return href;
        var hash = '', i = href.indexOf('#');
        if (i >= 0) { hash = href.slice(i); href = href.slice(0, i); }
        var q = href.indexOf('?');
        if (q >= 0 && ('&' + href.slice(q + 1)).indexOf('&' + key + '=') >= 0) return href + hash;
        return href + (q >= 0 ? '&' : '?') + key + '=' + value + hash;
    }
    main.querySelectorAll('a[href]').forEach(function (a) {
        if (a.hasAttribute('data-exempted-tick')) return;
        var h = a.getAttribute('href');
        var c = carry(h);
        if (c !== h) a.setAttribute('href', c);
    });
    main.querySelectorAll('form').forEach(function (f) {
        if ((f.getAttribute('method') || 'get').toLowerCase() !== 'get') return;
        if (f.querySelector('input[name="' + key + '"]')) return;
        var input = document.createElement('input');
        input.type = 'hidden'; input.name = key; input.value = value;
        f.appendChild(input);
    });
})();
