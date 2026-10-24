// Minimal DOM shim: just enough to execute the report's inline script without a browser or jsdom.
const fs = require("fs");
const html = fs.readFileSync(process.argv[2], "utf8");
const hash = process.argv[3] || "";
function mk(tag, attrs, extra) {
  const ds = {};
  for (const [k, v] of Object.entries(attrs)) if (k.startsWith("data-")) ds[k.slice(5)] = v;
  const cls = (attrs.class || "").split(/\s+/).filter(Boolean);
  const aria = {};
  return Object.assign({ tag, dataset: ds, hidden: false, open: false, id: attrs.id || "", next: null, textContent: "", onclick: null,
    classList: { contains: (c) => cls.includes(c) }, setAttribute(k, v) { aria[k] = v; }, getAttribute: (k) => aria[k], aria,
    get nextElementSibling() { return this.next; } }, extra || {});
}
function attrsOf(s) { const o = {}; for (const m of s.matchAll(/([\w-]+)="([^"]*)"/g)) o[m[1]] = m[2]; return o; }
const blocks = [], cards = [], mods = [], stats = [], byId = {};
const bodyStart = html.indexOf("<h1>");
const modsAt = html.indexOf('id="mods"'), statAt = html.indexOf('id="stat"'), toolsAt = html.indexOf('class="tools"');
for (const m of html.matchAll(/<(button|h2|details)\b([^>]*)>/g)) {
  const a = attrsOf(m[2]), pos = m.index;
  if (m[1] === "button") {
    const el = mk("button", a);
    if ((a.class || "").split(/\s+/).includes("c")) cards.push(el);
    else if (pos > modsAt && pos < statAt) mods.push(el);
    else if (pos > statAt && pos < toolsAt) stats.push(el);
    else el._tool = true, byId[a.id] = el;
  } else if (m[1] === "h2" && a["data-mod"] !== undefined) blocks.push(mk("h2", a));
  else if (m[1] === "details") blocks.push(mk("details", a));
}
for (let i = 0; i < blocks.length - 1; i++) blocks[i].next = blocks[i + 1];
const countEl = mk("div", {}); byId.count = countEl;
for (const id of ["exp", "col", "reset"]) byId[id] = byId[id] || mk("button", { id });
const items = blocks.filter((b) => b.tag === "details"), heads = blocks.filter((b) => b.tag === "h2");
for (const it of items) it.classList = { contains: (c) => c === "f" };
const sel = {
  ".f": items, "h2[data-mod]": heads, ".c": cards, "#mods button": mods, "#stat button": stats,
  ".c[data-sev]": cards.filter((c) => c.dataset.sev), ".c[data-s]": cards.filter((c) => c.dataset.s),
};
global.document = { querySelectorAll: (s) => { if (!(s in sel)) throw new Error("unsupported selector " + s); return sel[s]; },
  getElementById: (id) => byId[id] };
global.location = { hash, pathname: "/r.html", search: "" };
global.window = { addEventListener() {} };
global.history = { replaceState: (_a, _b, u) => { global.__url = u; } };
const script = html.slice(html.indexOf(">", html.lastIndexOf("<script")) + 1, html.lastIndexOf("</script>"));  // nosemgrep: unknown-value-with-script-tag  (test shim reading our own generated report, not browser code)
eval(script);
const visible = () => items.filter((i) => !i.hidden).map((i) => i.dataset.cat + ":" + i.dataset.st + ":" + (i.dataset.sev || "-"));
const out = { initial: { visible: visible(), count: countEl.textContent } };
const click = (el) => el.onclick();
const card = (sev) => cards.find((c) => c.dataset.sev === sev);
click(card("critical")); out.critical = { visible: visible(), count: countEl.textContent, pressed: card("critical").aria["aria-pressed"], url: global.__url };
click(card("critical")); out.toggled_off = { visible: visible(), url: global.__url };
click(card("high")); out.high = { visible: visible(), headsHidden: heads.map((h) => h.hidden) };
click(mods.find((m) => m.dataset.m === "ca")); out.high_exchange = { visible: visible() };
click(byId.reset); out.reset = { visible: visible() };
click(cards.find((c) => c.dataset.s === "PASS")); out.passed = { visible: visible() };
click(byId.reset); click(stats.find((s) => s.dataset.s === "issues")); out.issues = { visible: visible() };
click(byId.exp); out.expanded = items.every((i) => i.open);
console.log(JSON.stringify(out));
