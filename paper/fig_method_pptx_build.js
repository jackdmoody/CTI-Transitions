const pptxgen = require('pptxgenjs');
const pres = new pptxgen();
const S = 0.8;                 // inches per TikZ cm (about 2x print size)
const X0 = -0.1, YTOP = 3.95;
const W = 17.75 * S, H = 5.5 * S;
pres.defineLayout({ name: 'FIG', width: W, height: H });
pres.layout = 'FIG';
pres.title = 'W2 method figure (Figure 1)';

const FONT = 'Times New Roman';
const F_HEAD = 16, F_BODY = 12;            // footnotesize / scriptsize at 2x
const cR = '2A78D6', cB = 'EB6834', cG = '1BAF7A', INK = '333333';
const tint = (hex, p) => { const n = parseInt(hex, 16); const ch = [(n>>16)&255,(n>>8)&255,n&255].map(c => Math.round(255 - p*(255-c))); return ch.map(c => c.toString(16).padStart(2,'0')).join('').toUpperCase(); };
const gray = (pct) => { const v = Math.round(255*(1-pct/100)); return [v,v,v].map(c=>c.toString(16).padStart(2,'0')).join('').toUpperCase(); };
const X = (x) => (x - X0) * S, Y = (y) => (YTOP - y) * S;
const box = (cx, cy, w, h) => ({ x: X(cx - w/2), y: Y(cy + h/2), w: w*S, h: h*S });

const slide = pres.addSlide();
slide.background = { color: 'FFFFFF' };
slide.addNotes('Editable version of Figure 1. Edit here, then File > Export > PDF (or Save As PDF) and replace fig_method.pdf; the paper includes it at \\textwidth, which scales this canvas to about half size, so 16 pt and 12 pt here print at roughly 8 pt and 6 pt. Matrix glyphs and example tactics are schematic.');

const base = { fontFace: FONT, color: INK, margin: 3, isTextBox: true };
const R = (text, o = {}) => ({ text, options: o });
const rbox = (name, geom, runs, fillHex, opts = {}) => slide.addText(runs, Object.assign({}, base, geom, {
  objectName: name, shape: pres.shapes.ROUNDED_RECTANGLE, rectRadius: 0.06,
  fill: { color: fillHex }, line: { color: gray(55), width: 0.9, dashType: opts.dash || 'solid' },
  align: 'center', valign: opts.valign || 'middle', fontSize: F_BODY, lineSpacingMultiple: 0.95,
}, opts.extra || {}));
const arrow = (name, x1, y1, x2, y2, o = {}) => {   // x,y in TikZ cm
  const up = y2 > y1;
  slide.addShape(pres.shapes.LINE, {
    objectName: name, x: X(Math.min(x1, x2)), y: Y(Math.max(y1, y2)), w: Math.abs(x2 - x1) * S, h: Math.abs(y2 - y1) * S,
    line: Object.assign({ color: o.color || gray(70), width: o.width || 1.1 }, o.noHead ? {} : (up ? { beginArrowType: 'triangle' } : { endArrowType: 'triangle' })),
  });
};
const chip = (name, cx, cy, w, text) => slide.addText(text, Object.assign({}, base, box(cx, cy, w, 0.4), {
  objectName: name, shape: pres.shapes.ROUNDED_RECTANGLE, rectRadius: 0.04, fill: { color: 'FFFFFF' },
  line: { color: gray(45), width: 0.7 }, fontSize: F_BODY, align: 'center', valign: 'middle', margin: 1,
}));

// ---------------- inputs ----------------
rbox('input-R', box(1.55, 3.15, 3.1, 0.95), [R('CTI reports ', { bold: true, fontSize: F_HEAD }), R('(R)', { bold: true, fontSize: F_HEAD, color: cR, breakLine: true }), R('23 reports, 2018–2025')], tint(cR, 0.10));
rbox('input-B', box(1.55, 1.85, 3.1, 0.95), [R('Actor name + aliases ', { bold: true, fontSize: F_HEAD }), R('(B)', { bold: true, fontSize: F_HEAD, color: cB, breakLine: true }), R("no report: actor name and aliases only")], tint(cB, 0.10));
rbox('input-ATTK', box(1.55, 0.7, 3.1, 0.8), [R('ATT&CK groups ', { bold: true, fontSize: 14 }), R('(ATTK)', { bold: true, fontSize: 14, breakLine: true }), R("actor's techniques per tactic, "), R('n', { italic: true }), R('i', { italic: true, subscript: true })], gray(6));

// ---------------- LLM extraction ----------------
rbox('llm-extraction', box(5.1, 2.5, 3.0, 2.45), [
  R('LLM extraction', { bold: true, fontSize: F_HEAD, breakLine: true }),
  R('frozen prompt, same chunks', { breakLine: true }),
  R(' ', { fontSize: 3, breakLine: true }),
  R('F: Opus 5.5 (API, ×5)', { breakLine: true }),
  R('G: GPT-6 Astra (API, ×5)', { breakLine: true }),
  R('Q: Qwen3-14B', { breakLine: true }),
  R('M, M3: Ministral 3 14B, 3B', { breakLine: true }),
  R('Q, M, M3 run on a laptop', { color: gray(60) }),
], gray(4), { valign: 'top' });

// ---------------- validate + aggregate ----------------
rbox('validate-aggregate', box(8.825, 2.5, 3.55, 2.45), [
  R('Validate, then aggregate', { bold: true, fontSize: F_HEAD, breakLine: true }),
  R(' ', { fontSize: 15, breakLine: true }),
  R(' ', { fontSize: 6, breakLine: true }),
  R('schema: 14 tactics, '), R('i', { italic: true }), R(' ≠ '), R('j', { italic: true, breakLine: true }),
  R('quote match checked (R); reported, not filtered', { breakLine: true }),
  R('one count per report, α = 0.5 (Eq. 1)'),
], gray(4), { valign: 'top' });
chip('chip-initial-access', 8.145, 3.125, 1.5, 'Initial Access');
chip('chip-execution', 9.685, 3.125, 1.15, 'Execution');
arrow('arrow-chip-example', 8.895, 3.125, 9.11, 3.125, { width: 0.8, color: gray(60) });

// ---------------- ATTK construction ----------------
rbox('attk-construction', box(7.1, 0.7, 7.0, 0.8), [
  R('counts ', { fontSize: F_HEAD }), R('C', { italic: true, fontSize: F_HEAD }), R('(', { fontSize: F_HEAD }), R('i', { italic: true, fontSize: F_HEAD }), R(',', { fontSize: F_HEAD }), R('j', { italic: true, fontSize: F_HEAD }), R(') = ', { fontSize: F_HEAD }),
  R('n', { italic: true, fontSize: F_HEAD }), R('i', { italic: true, subscript: true, fontSize: F_HEAD }), R('n', { italic: true, fontSize: F_HEAD }), R('j', { italic: true, subscript: true, fontSize: F_HEAD }), R(', then Eq. 1', { fontSize: F_HEAD, breakLine: true }),
  R('rows nearly identical: tactic frequency, no order'),
], gray(6));

// ---------------- prior glyphs (schematic 6x6 matrices) ----------------
const glyph = (name, cx, cy, hex, weights) => {
  const cell = 0.15, x0 = cx - 0.45, ytop = cy + 0.45;
  weights.forEach((w, k) => {
    const r = Math.floor(k / 6), c = k % 6;
    const gx = x0 + c * cell, gy = ytop - r * cell;
    if (r === c) {
      slide.addShape(pres.shapes.RECTANGLE, { objectName: `${name}-diag-${r}`, x: X(gx), y: Y(gy), w: cell*S, h: cell*S, fill: { color: 'FFFFFF' }, line: { type: 'none' } });
      slide.addShape(pres.shapes.LINE, { objectName: `${name}-diagline-${r}`, x: X(gx), y: Y(gy), w: cell*S, h: cell*S, flipV: true, line: { color: gray(25), width: 0.4 } });
    } else {
      slide.addShape(pres.shapes.RECTANGLE, { objectName: `${name}-cell-${r}-${c}`, x: X(gx), y: Y(gy), w: cell*S, h: cell*S, fill: { color: tint(hex, 0.10 + 0.30 * w) }, line: { type: 'none' } });
    }
  });
  slide.addShape(pres.shapes.RECTANGLE, { objectName: `${name}-frame`, x: X(cx - 0.45), y: Y(cy + 0.45), w: 0.9*S, h: 0.9*S, fill: { type: 'none' }, line: { color: gray(45), width: 0.6 } });
};
glyph('glyph-R', 11.4, 3.15, cR, [0,3,0,0,1,0, 0,0,0,2,0,1, 1,0,0,0,3,0, 0,0,0,0,0,3, 0,0,2,1,0,0, 3,0,0,0,1,0]);
glyph('glyph-B', 11.4, 1.85, cB, [0,0,3,0,0,1, 2,0,0,0,1,0, 0,0,0,3,0,0, 0,1,0,0,0,2, 0,0,0,0,0,3, 0,2,0,1,0,0]);
glyph('glyph-ATTK', 11.4, 0.7, '333333', [0,1,3,0,2,1, 2,0,3,0,2,1, 2,1,0,0,2,1, 2,1,3,0,2,1, 2,1,3,0,0,1, 2,1,3,0,2,0]);
slide.addText([R('report-supported kernels ', { italic: true }), R('P̂', { italic: true }), R('a', { italic: true, subscript: true })],
  Object.assign({}, base, box(11.4, 3.78, 2.2, 0.32), { objectName: 'label-actor-priors', fontSize: F_BODY, color: gray(60), align: 'center', valign: 'middle', margin: 0 }));

// ---------------- ground truth ----------------
rbox('ground-truth-plan', box(1.55, -1.0, 3.1, 0.8), [R('MITRE emulation plan', { bold: true, fontSize: F_HEAD, breakLine: true }), R('4 actors, 15–79 steps')], tint(cG, 0.10));
rbox('ground-truth-sequence', box(7.1, -1.0, 7.0, 0.8), [R('')], tint(cG, 0.10));
slide.addText([R('ground truth ', { bold: true, fontSize: F_HEAD }), R('g', { bold: true, italic: true, fontSize: F_HEAD })],
  Object.assign({}, base, { objectName: 'label-ground-truth', x: X(3.68), y: Y(-0.62), w: 2.6*S, h: 0.36*S, align: 'left', valign: 'middle', margin: 0 }));
slide.addText('repeats collapsed', Object.assign({}, base, { objectName: 'label-repeats-collapsed', x: X(8.0), y: Y(-0.63), w: 2.52*S, h: 0.34*S, fontSize: F_BODY, color: gray(60), align: 'right', valign: 'middle', margin: 0 }));
chip('gt-chip-1', 4.52, -1.17, 1.5, 'Initial Access');
chip('gt-chip-2', 6.12, -1.17, 1.15, 'Execution');
chip('gt-chip-3', 7.66, -1.17, 1.3, 'Persistence');
chip('gt-chip-4', 9.16, -1.17, 1.15, 'Discovery');
arrow('gt-arrow-1', 5.27, -1.17, 5.545, -1.17, { width: 0.8, color: gray(60) });
arrow('gt-arrow-2', 6.695, -1.17, 7.01, -1.17, { width: 0.8, color: gray(60) });
arrow('gt-arrow-3', 8.31, -1.17, 8.585, -1.17, { width: 0.8, color: gray(60) });
slide.addText('…', Object.assign({}, base, { objectName: 'gt-ellipsis', x: X(9.78), y: Y(-0.98), w: 0.5*S, h: 0.38*S, fontSize: F_BODY, align: 'center', valign: 'middle', margin: 0 }));

// ---------------- leakage wall ----------------
slide.addShape(pres.shapes.LINE, { objectName: 'leakage-wall', x: X(0), y: Y(-0.22), w: 12.55*S, h: 0, line: { color: gray(70), width: 1.4, dashType: 'dash' } });
slide.addText('leakage wall: the 204 links the plans cite are excluded from the report corpus', Object.assign({}, base, box(5.7, -0.22, 6.9, 0.36), {
  objectName: 'leakage-wall-label', fontSize: F_BODY, italic: true, fill: { color: 'FFFFFF' }, align: 'center', valign: 'middle', margin: 0 }));

// ---------------- scoring ----------------
rbox('score', box(15.2, 1.95, 4.7, 3.35), [R('')], gray(10));
slide.addText([R('Score each prior against ', { bold: true }), R('g', { bold: true, italic: true })],
  Object.assign({}, base, { objectName: 'score-title', x: X(12.85), y: Y(3.6), w: 4.7*S, h: 0.42*S, fontSize: F_HEAD, align: 'center', valign: 'middle', margin: 0 }));
slide.addText([
  R('Support: ', { bold: true }), R('edge-F1 ÷ size-matched chance', { breakLine: true }),
  R(' ', { fontSize: 4, breakLine: true }),
  R('Fit: ', { bold: true }), R('IG = (1/'), R('L', { italic: true }), R(') Σ'), R('t', { italic: true, subscript: true }), R(' log'), R('2', { subscript: true }), R(' 13 '),
  R('P̂', { italic: true }), R('a', { italic: true, subscript: true }), R('('), R('g', { italic: true }), R('t−1', { italic: true, subscript: true }), R(', '), R('g', { italic: true }), R('t', { italic: true, subscript: true }), R(')', { breakLine: true }),
  R('    bits per transition; 0 for the uniform chain', { breakLine: true }),
  R(' ', { fontSize: 6, breakLine: true }),
  R('Comparisons', { bold: true, breakLine: true }),
  R('R', { bold: true, color: cR }), R(' vs '), R('B', { bold: true, color: cB }), R(': with vs without reports (H2)', { breakLine: true }),
  R('F vs G: a second vendor', { breakLine: true }),
  R('F vs Q, M, M3: model size (H3)', { breakLine: true }),
  R('each prior vs every plan: specificity (H4)'),
], Object.assign({}, base, { objectName: 'score-body', x: X(12.99), y: Y(3.17), w: 4.5*S, h: 2.75*S, fontSize: F_BODY, align: 'left', valign: 'top', margin: 0, lineSpacingMultiple: 1.0 }));

rbox('detector-link', box(15.7, -1.0, 3.75, 1.0), [R("IG: average log-score change over uniform per transition (Eq. 3); case studies on OTRF and OpTC")], 'FFFFFF', { dash: 'dash' });

// ---------------- arrows ----------------
arrow('arrow-R-in', 3.1, 3.15, 3.6, 3.15);
arrow('arrow-B-in', 3.1, 1.85, 3.6, 1.85);
arrow('arrow-R-llm', 6.6, 3.15, 7.05, 3.15);
arrow('arrow-B-llm', 6.6, 1.85, 7.05, 1.85);
arrow('arrow-R-prior', 10.6, 3.15, 10.9, 3.15);
arrow('arrow-B-prior', 10.6, 1.85, 10.9, 1.85);
arrow('arrow-ATTK-in', 3.1, 0.7, 3.6, 0.7);
arrow('arrow-ATTK-prior', 10.6, 0.7, 10.9, 0.7);
[['R', 3.15, cR], ['B', 1.85, cB], ['ATTK', 0.7, INK]].forEach(([l, y, col]) => {
  arrow(`arrow-${l}-score`, 11.9, y, 12.85, y);
  slide.addText(l, Object.assign({}, base, { objectName: `label-${l}`, x: X(11.9), y: Y(y + 0.42), w: 0.95*S, h: 0.38*S, fontSize: F_BODY, bold: true, color: col, align: 'center', valign: 'bottom', margin: 0 }));
});
arrow('arrow-plan-seq', 3.1, -1.0, 3.6, -1.0);
arrow('arrow-gt-elbow-h', 10.6, -1.0, 13.2, -1.0, { noHead: true });
arrow('arrow-gt-elbow-v', 13.2, -1.0, 13.2, 0.275);
arrow('arrow-score-detector', 15.7, 0.275, 15.7, -0.5);

pres.writeFile({ fileName: 'W2_fig_method_v2.pptx' }).then(f => console.log('wrote', f));
