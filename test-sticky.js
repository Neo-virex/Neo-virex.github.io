const toc = document.getElementById('toc-wrapper');
const panel = document.getElementById('panel-wrapper');
const row = panel.parentElement;
console.log('TOC position:', window.getComputedStyle(toc).position);
console.log('TOC top:', window.getComputedStyle(toc).top);
console.log('Panel height:', panel.clientHeight);
console.log('Row height:', row.clientHeight);
