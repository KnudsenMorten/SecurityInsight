// The management presentation's form (Pages/Management/Presentation.cshtml): the section presets, and the last choices
// remembered in THIS browser (sections, Protection Score view, audience, number format, the AI notes) -- a convenience only:
// nothing is stored on the server, and the form works without it.
(function () {
    'use strict';
    var form = document.querySelector('[data-pres-form]');
    if (!form) return;
    var KEY = 'si-presentation-choices';

    function boxes() { return Array.prototype.slice.call(form.querySelectorAll('[data-pres-section]')); }
    function choose(keys) { boxes().forEach(function (b) { b.checked = keys.indexOf(b.value) >= 0; }); }

    var presets = form.querySelector('[data-pres-presets]');
    if (presets) {
        presets.hidden = false;
        presets.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-pres-preset]');
            if (!btn) return;
            var keys = (btn.getAttribute('data-keys') || '').split(',').filter(function (k) { return k; });
            choose(keys);
        });
    }

    function read() {
        try { var v = window.localStorage.getItem(KEY); return v ? JSON.parse(v) : null; } catch (e) { return null; }
    }
    function save() {
        try {
            var v = { sections: boxes().filter(function (b) { return b.checked; }).map(function (b) { return b.value; }) };
            form.querySelectorAll('[data-pres-remember]').forEach(function (el) {
                v[el.getAttribute('data-pres-remember')] = el.type === 'checkbox' ? el.checked : el.value;
            });
            window.localStorage.setItem(KEY, JSON.stringify(v));
        } catch (e) { /* no storage: nothing is remembered */ }
    }

    var last = read();
    if (last) {
        if (Array.isArray(last.sections) && last.sections.length) choose(last.sections);
        form.querySelectorAll('[data-pres-remember]').forEach(function (el) {
            var k = el.getAttribute('data-pres-remember');
            if (!(k in last)) return;
            if (el.type === 'checkbox') el.checked = !!last[k];
            else if (Array.prototype.some.call(el.options || [], function (o) { return o.value === last[k]; })) el.value = last[k];
        });
    }
    form.addEventListener('submit', save);
})();
