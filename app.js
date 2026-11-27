/* 수학Ⅰ 개념 노트 — 단원마다 7부분: 왜 배우나 · 누가 왜 만들었나 · 어디에 쓰이나 · 개념의 뿌리(인터랙티브 그래프)
 *   · 자주 흔들리는 지점 · 설명해 보기 · 개념 지도.
 * 게시된 사이트: data/content.enc (비밀번호로 암호화한 묶음, scripts/publish_web.py 가 만든다)
 *   암호화 형식은 01_ENG1~3 과 같다: PBKDF2-SHA256 → AES-256-GCM (+gzip).
 * 로컬 미리보기(web/ 폴더): content.enc 가 없으면 data/*.json 평문을 읽는다.
 * 화면:  #/ 홈 · #/u/<단원>/<탭> · #/ask?ref=
 * 글 표기: $인라인 수식$  $$가운데 수식$$ (KaTeX) · **굵게** · ==강조== · __밑줄__
 */
(() => {
  "use strict";
  const EXPLAIN_STORE = "math1.explain.v1";   // { 질문id: { level: ok|half|no, text } }
  const $ = (s, el = document) => el.querySelector(s);
  const view = $("#view");
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 */ } },
    del(k) { try { localStorage.removeItem(k); } catch { /* */ } },
  };
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const tex = (t, display = false) => (window.katex
    ? katex.renderToString(t, { displayMode: display, throwOnError: false, output: "html" })
    : esc(display ? `$$${t}$$` : `$${t}$`));
  // 수식을 먼저 빼 두고(KaTeX), 나머지에 굵게 · 강조 표기를 입힌다
  const fmt = (s) => {
    const math = [];
    const keep = String(s ?? "").replace(/\\\$/g, "\u0001")
      .replace(/\$\$([\s\S]+?)\$\$|\$([^$]+?)\$/g, (m, d, i) => {
        math.push(d !== undefined ? `<span class="mdisp">${tex(d, true)}</span>` : tex(i));
        return `\u0000${math.length - 1}\u0000`;
      });
    return esc(keep)
      .replace(/\*\*(.+?)\*\*/g, "<b>$1</b>")
      .replace(/==(.+?)==/g, "<mark>$1</mark>")
      .replace(/__(.+?)__/g, "<u>$1</u>")
      .replace(/\n/g, "<br>")
      .replace(/\u0001/g, "$")
      .replace(/\u0000(\d+)\u0000/g, (m, k) => math[Number(k)]);
  };
  const paras = (arr) => [].concat(arr || []).map((t) => (/^\$\$[\s\S]*\$\$$/.test(t.trim()) ? fmt(t) : `<p>${fmt(t)}</p>`)).join("");
  const feat = (k) => ((window.SITE_CONFIG || {}).features || {})[k] !== false;
  const cssVar = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

  // ---------- 데이터 ----------
  let index = null;
  let bundle = null;
  const unitCache = new Map();
  async function getJSON(url) {
    const r = await fetch(url, { cache: "no-cache" });
    if (!r.ok) throw new Error(`${url} ${r.status}`);
    return r.json();
  }
  async function loadIndex() {
    if (!index) index = bundle ? bundle.index : await getJSON("data/index.json");
    return index;
  }
  async function loadUnit(id) {
    if (bundle) {
      if (!bundle.units[id]) throw new Error(`단원 없음: ${id}`);
      return bundle.units[id];
    }
    if (!unitCache.has(id)) unitCache.set(id, await getJSON(`data/units/${encodeURIComponent(id)}.json`));
    return unitCache.get(id);
  }
  const allUnits = (idx) => idx.chapters.flatMap((ch) => ch.units.map((u) => ({ ...u, chapter: ch })));

  // ---------- 설명 기록 (이 기기) ----------
  const explained = (() => {
    let d = {};
    try { d = JSON.parse(store.get(EXPLAIN_STORE) || "{}") || {}; } catch { d = {}; }
    return {
      get: (id) => d[id],
      put(id, patch) { d[id] = { ...(d[id] || {}), ...patch }; store.set(EXPLAIN_STORE, JSON.stringify(d)); },
    };
  })();

  // ---------- 잠금 (암호화된 내용) ----------
  const KEY_STORE = "math1.key.v1";
  const b64 = (t) => Uint8Array.from(atob(t), (c) => c.charCodeAt(0));
  const b64e = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  let enc = null;
  async function deriveKey(password, salt, iter) {
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
      base, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }
  async function decryptWith(key) {
    let buf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(enc.iv) }, key, b64(enc.ct));
    if (enc.z === "gzip") {
      const ds = new Blob([buf]).stream().pipeThrough(new DecompressionStream("gzip"));
      buf = await new Response(ds).arrayBuffer();
    }
    return JSON.parse(new TextDecoder().decode(buf));
  }
  async function tryStoredKey() {
    const raw = store.get(KEY_STORE);
    if (!raw) return false;
    try {
      const s = JSON.parse(raw);
      if (s.salt !== enc.salt || s.iter !== enc.iter) return false;
      const key = await crypto.subtle.importKey("raw", b64(s.key), "AES-GCM", false, ["decrypt"]);
      bundle = await decryptWith(key);
      return true;
    } catch { store.del(KEY_STORE); return false; }
  }
  function showLock(msg) {
    $("#app").hidden = true;
    $("#lock").hidden = false;
    $("#lockMsg").textContent = msg || "";
    $("#pw").focus();
  }
  async function unlock(e) {
    e.preventDefault();
    const btn = $("#unlockBtn");
    btn.disabled = true; btn.textContent = "여는 중…";
    try {
      const key = await deriveKey($("#pw").value, b64(enc.salt), enc.iter);
      bundle = await decryptWith(key);
      if ($("#remember").checked) {
        const raw = await crypto.subtle.exportKey("raw", key);
        store.set(KEY_STORE, JSON.stringify({ salt: enc.salt, iter: enc.iter, key: b64e(raw) }));
      }
      $("#pw").value = "";
      start();
    } catch {
      showLock("비밀번호가 맞지 않습니다.");
    } finally {
      btn.disabled = false; btn.textContent = "열기";
    }
  }
  function lockNow() { store.del(KEY_STORE); bundle = null; index = null; showLock(""); }

  // ---------- 난이도 기록 · 질문하기 (01_ENG1~3 과 같은 설문지) ----------
  const DEVICE_STORE = "math1.device";
  let dev = store.get(DEVICE_STORE);
  if (!dev) { dev = Math.random().toString(36).slice(2, 10); store.set(DEVICE_STORE, dev); }
  function sendRating(cat, item, kind, value) {
    const c = (window.SITE_CONFIG || {}).rating;
    if (!c?.url) return;
    const f = c.fields;
    const body = new URLSearchParams();
    body.set(f.cat, cat); body.set(f.item, item); body.set(f.kind, kind); body.set(f.value, value); body.set(f.device, dev);
    fetch(c.url, { method: "POST", mode: "no-cors", body }).catch(() => {});
  }
  function feedbackUrl(ref) {
    const f = (window.SITE_CONFIG || {}).feedback || {};
    if (!f.url) return "";
    const q = new URLSearchParams({ usp: "pp_url" });
    if (f.prefill?.category) q.set(f.prefill.category, f.categoryValue || "수학Ⅰ");
    if (f.prefill?.ref && ref) q.set(f.prefill.ref, ref);
    return `${f.url}?${q}`;
  }
  const rateBar = (cat, item, opts = ["이해됨:이해됐어요", "헷갈림:아직 헷갈려요", "설명 더:설명 더 ＋"]) =>
    `<div class="rate" data-cat="${esc(cat)}" data-item="${esc(item)}"><span class="lbl">이 설명은</span>
      ${opts.map((o) => { const [v, l] = o.split(":"); return `<button type="button" data-v="${esc(v)}">${esc(l)}</button>`; }).join("")}
      <span class="sent" hidden>✓ 전달됨</span></div>`;

  // ---------- 홈 ----------
  function unitProgress(u) {
    const ids = (u.explainIds || []);
    return ids.filter((id) => explained.get(id)?.level === "ok").length;
  }
  async function renderHome(idx) {
    const units = allUnits(idx);
    const ready = units.filter((u) => u.status === "ready");
    // 홈의 진행 막대: 설명해 보기 질문 중 '설명할 수 있다' 개수
    for (const u of ready) {
      const full = await loadUnit(u.id);
      u.explainIds = (full.explain || []).map((e) => e.id);
    }
    view.innerHTML = `
      <section class="hero">
        <h2 style="margin:0">수학Ⅰ 개념 노트</h2>
        <p class="muted small">문제 풀이 요령이 아니라, 공식이 왜 그렇게 생겼는지를 내 말로 설명할 수 있게 만드는 노트입니다.</p>
      </section>
      <div class="card how small">
        <b>단원마다 7단계</b>
        <ol class="flow">${TABS.map((t) => `<li>${t.icon} ${esc(t.label)}</li>`).join("")}</ol>
        <span class="muted">마지막에 '설명해 보기'에서 친구에게 설명하듯 적어 보고, 모범 설명과 비교합니다.</span>
      </div>
      ${idx.chapters.map((ch) => `<div class="group-title">${esc(ch.no)}. ${esc(ch.title)}</div>
        <div class="cat-list">${ch.units.map((x) => unitRow(units.find((u) => u.id === x.id))).join("")}</div>`).join("")}`;
  }
  function unitRow(u) {
    if (u.status !== "ready") {
      return `<div class="cat planned"><div class="cat-head"><span class="cat-title">${esc(u.title)}</span><span class="pill gray">준비 중</span></div>
        <div class="cat-sub">${esc(u.subtitle || "")}</div></div>`;
    }
    const n = u.explainIds.length;
    const done = unitProgress(u);
    return `<a class="cat" href="#/u/${esc(u.id)}">
      <div class="cat-head"><span class="cat-title">${esc(u.title)}</span>${done === n && n ? `<span class="pill good">설명 완료</span>` : ""}</div>
      <div class="cat-sub">${esc(u.subtitle || "")}</div>
      <div class="bar"><span style="width:${n ? Math.round((done / n) * 100) : 0}%"></span></div>
      <div class="cat-sub">개념 ${u.counts.roots} · 흔들리는 지점 ${u.counts.pitfalls} · 설명해 보기 ${done}/${n}</div></a>`;
  }

  // ---------- 단원 ----------
  const TABS = [
    { id: "why", label: "왜 배우나", short: "왜?", icon: "🤔" },
    { id: "history", label: "누가 왜 만들었나", short: "역사", icon: "📜", feat: "history" },
    { id: "uses", label: "지금 어디에 쓰이나", short: "쓰임", icon: "🌍" },
    { id: "roots", label: "개념의 뿌리", short: "개념", icon: "🌱" },
    { id: "pitfalls", label: "자주 흔들리는 지점", short: "함정", icon: "⚠️" },
    { id: "explain", label: "설명해 보기", short: "설명", icon: "🗣️" },
    { id: "map", label: "개념 지도", short: "지도", icon: "🗺️" },
  ];
  const tabsFor = (u) => TABS.filter((t) => (t.id !== "history" || u.history) && (!t.feat || feat(t.feat)));

  async function renderUnit(id, tab) {
    const idx = await loadIndex();
    const units = allUnits(idx);
    const meta = units.find((x) => x.id === id);
    const u = await loadUnit(id);
    const tabs = tabsFor(u);
    redraw.clear();
    if (!tabs.some((t) => t.id === tab)) tab = tabs[0].id;
    const ti = tabs.findIndex((t) => t.id === tab);
    view.innerHTML = `
      <a class="crumb" href="#/">← 전체 단원</a>
      <div class="cat-top"><div class="muted small">${esc(meta?.chapter.no || "")}. ${esc(meta?.chapter.title || "")}</div>
        <h2>${esc(u.title)}</h2><div class="one-line">${fmt(u.oneLine)}</div></div>
      <div class="tabs" role="tablist">${tabs.map((t, k) => `<button role="tab" aria-selected="${t.id === tab}" data-tab="${t.id}"><span class="tn">${k + 1}</span>${esc(t.short)}</button>`).join("")}</div>
      <h3 class="tab-h">${tabs[ti].icon} ${esc(tabs[ti].label)}</h3>
      <div id="tabBody"></div>
      <div class="pager">
        ${ti > 0 ? `<a class="btn ghost" href="#/u/${esc(id)}/${tabs[ti - 1].id}">← ${esc(tabs[ti - 1].label)}</a>` : "<span></span>"}
        ${ti < tabs.length - 1 ? `<a class="btn" href="#/u/${esc(id)}/${tabs[ti + 1].id}">${esc(tabs[ti + 1].label)} →</a>` : nextUnitBtn(units, id)}
      </div>`;
    view.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { location.hash = `#/u/${id}/${b.dataset.tab}`; }));
    const sel = view.querySelector(".tabs [aria-selected=true]");
    if (sel) sel.scrollIntoView({ block: "nearest", inline: "center" });
    const body = $("#tabBody");
    ({ why: tabWhy, history: tabHistory, uses: tabUses, roots: tabRoots, pitfalls: tabPitfalls, explain: tabExplain, map: tabMap })[tab](u, body);
  }
  function nextUnitBtn(units, id) {
    const i = units.findIndex((x) => x.id === id);
    const n = units.slice(i + 1).find((x) => x.status === "ready");
    return n ? `<a class="btn" href="#/u/${esc(n.id)}">다음 단원: ${esc(n.title)} →</a>` : `<a class="btn" href="#/">전체 단원으로</a>`;
  }

  function tabWhy(u, body) {
    const w = u.why;
    body.innerHTML = `<article class="card hook-card"><div class="hook">${fmt(w.hook)}</div></article>
      <article class="card sec"><div class="body">${paras(w.body)}</div>
      ${w.question ? `<div class="tip">✍️ ${fmt(w.question)}</div>` : ""}</article>`;
  }
  function tabHistory(u, body) {
    const h = u.history;
    body.innerHTML = `${h.people?.length ? `<div class="people">${h.people.map((p) => `<div class="person">
        <div class="p-name">${esc(p.name)}</div><div class="p-years muted small">${esc(p.years || "")}</div>
        <div class="p-role small">${fmt(p.role)}</div></div>`).join("")}</div>` : ""}
      <article class="card sec"><div class="body">${paras(h.story)}</div>
      ${h.takeaway ? `<div class="tip">💡 ${fmt(h.takeaway)}</div>` : ""}</article>`;
  }
  function tabUses(u, body) {
    body.innerHTML = u.uses.map((x) => `<article class="card sec use">
        <h3>${x.icon ? `${x.icon} ` : ""}${fmt(x.title)}</h3><div class="body">${paras(x.body)}</div>
      </article>`).join("");
  }
  function tableHtml(t) {
    return `<div class="tbl-wrap"><table><thead><tr>${t.head.map((h) => `<th>${fmt(h)}</th>`).join("")}</tr></thead>
      <tbody>${t.rows.map((r) => `<tr>${r.map((c) => `<td>${fmt(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }
  function tabRoots(u, body) {
    body.innerHTML = u.roots.map((r, k) => `<article class="card sec root" id="${esc(r.id)}">
        <div class="note-head"><span class="pill">개념 ${k + 1}</span>${r.tier === "deep" ? `<span class="pill fl">더 깊이</span>` : ""}</div>
        <h3>${fmt(r.heading)}</h3>
        <div class="body">${paras(r.body)}</div>
        ${r.formula ? `<div class="formula">${fmt(r.formula)}</div>` : ""}
        ${r.widget && feat("interactive") ? `<div class="wg" data-wg="${esc(r.widget.type)}" data-cfg="${esc(JSON.stringify(r.widget))}"></div>` : ""}
        ${r.table ? tableHtml(r.table) : ""}
        ${r.after?.length ? `<div class="body">${paras(r.after)}</div>` : ""}
        ${r.check ? `<div class="nsec"><div class="nlabel">⏱ 30초 확인</div><button type="button" class="drill-q">${fmt(r.check.q)}</button><span class="drill-a" hidden>${fmt(r.check.a)}</span></div>` : ""}
        ${r.tip ? `<div class="tip">${fmt(r.tip)}</div>` : ""}
        ${rateBar(u.id, r.id)}
      </article>`).join("");
    body.querySelectorAll(".wg").forEach((el) => {
      const fn = WIDGETS[el.dataset.wg];
      if (fn) { try { fn(el, JSON.parse(el.dataset.cfg)); } catch (e) { el.textContent = `그래프 오류: ${e.message}`; } }
    });
  }
  function tabPitfalls(u, body) {
    body.innerHTML = `<p class="small muted" style="margin:8px 0 0">왼쪽 생각이 왜 그럴듯해 보이는지, 어디서 어긋나는지를 보세요. 틀린 생각에도 이유가 있습니다.</p>`
      + u.pitfalls.map((p) => `<article class="card pit">
        <div class="pit-wrong"><span class="tag tag-no">흔한 생각</span> ${fmt(p.wrong)}</div>
        <div class="pit-right"><span class="tag tag-ok">바로잡기</span> ${fmt(p.right)}</div>
        <div class="body small">${paras(p.why)}</div>
        ${p.fix ? `<div class="tip">🧷 기억법: ${fmt(p.fix)}</div>` : ""}
        ${rateBar(u.id, p.id)}
      </article>`).join("");
  }
  const LEVELS = [["ok", "설명할 수 있다"], ["half", "반쯤"], ["no", "아직 못 하겠다"]];
  function tabExplain(u, body) {
    body.innerHTML = `<p class="small muted" style="margin:8px 0 0">공식을 모르는 친구에게 말로 설명한다고 생각하고 적어 보세요. 다 적은 뒤에 '비교하기'를 누르면 꼭 들어가야 할 내용과 모범 설명이 나옵니다.</p>`
      + u.explain.map((e, k) => {
        const s = explained.get(e.id) || {};
        return `<article class="card ex-q" data-id="${esc(e.id)}">
          <div class="q-meta"><span class="pill">설명 ${k + 1}</span>${e.tier === "deep" ? `<span class="pill fl">더 깊이</span>` : ""}
            ${s.level ? `<span class="pill ${s.level === "ok" ? "good" : s.level === "half" ? "student" : "bad"}">${LEVELS.find((l) => l[0] === s.level)[1]}</span>` : ""}</div>
          <div class="q-text">${fmt(e.q)}</div>
          ${e.hint ? `<details class="hint"><summary>힌트</summary><div class="small">${fmt(e.hint)}</div></details>` : ""}
          <textarea class="w-input" rows="4" placeholder="내 말로 설명해 보기 (수식은 2^0 처럼 써도 됩니다)">${esc(s.text || "")}</textarea>
          <button type="button" class="btn ghost small cmp" style="margin-top:8px">비교하기</button>
          <div class="cmp-body" hidden>
            <div class="nlabel" style="margin-top:12px">꼭 들어가야 할 내용 (내 설명에 있으면 체크)</div>
            <ul class="pts-check">${e.points.map((pt, j) => `<li><label><input type="checkbox" data-j="${j}"> <span>${fmt(pt)}</span></label></li>`).join("")}</ul>
            <div class="nlabel">모범 설명</div>
            <div class="model">${paras(e.model)}</div>
            <div class="self"><span class="small muted">나는 지금</span>${LEVELS.map(([v, l]) => `<button type="button" class="btn ghost small lv${s.level === v ? " on" : ""}" data-v="${v}">${l}</button>`).join("")}</div>
            ${feat("sendExplain") ? `<button type="button" class="linkish send">내 설명을 선생님께 보내기</button><span class="small sent-ok" hidden>✓ 보냈어요</span>` : ""}
          </div>
        </article>`;
      }).join("");
    body.querySelectorAll(".ex-q").forEach((card) => {
      const id = card.dataset.id;
      const ta = $("textarea", card);
      ta.addEventListener("input", () => explained.put(id, { text: ta.value }));
      $(".cmp", card).addEventListener("click", (ev) => { $(".cmp-body", card).hidden = false; ev.target.remove(); });
      card.querySelectorAll(".lv").forEach((b) => b.addEventListener("click", () => {
        explained.put(id, { level: b.dataset.v });
        card.querySelectorAll(".lv").forEach((x) => x.classList.toggle("on", x === b));
        const got = [...card.querySelectorAll(".pts-check input")].filter((c) => c.checked).length;
        sendRating(u.id, id, "설명", `${b.dataset.v} (${got}/${card.querySelectorAll(".pts-check input").length})`);
      }));
      const send = $(".send", card);
      if (send) send.addEventListener("click", () => {
        const t = ta.value.trim();
        if (!t) { ta.focus(); return; }
        sendRating(u.id, id, "설명글", t.slice(0, 1500));
        send.hidden = true; $(".sent-ok", card).hidden = false;
      });
    });
  }
  // 개념 지도: 노드는 HTML(수식 가능), 선은 그 아래 SVG. x 는 가로 % (중심), row 는 줄 번호.
  function tabMap(u, body) {
    const m = u.map;
    const ROW = 92;
    const rows = Math.max(...m.nodes.map((n) => n.row)) + 1;
    const H = rows * ROW;
    const pos = Object.fromEntries(m.nodes.map((n) => [n.id, { x: n.x, y: n.row * ROW + ROW / 2 }]));
    const kinds = { prev: "이미 배운 것", core: "이 단원", next: "앞으로 이어지는 곳" };
    body.innerHTML = `${m.intro ? `<p class="small muted" style="margin:8px 0 0">${fmt(m.intro)}</p>` : ""}
      <div class="legend small">${Object.entries(kinds).map(([k, l]) => `<span><i class="dot ${k}"></i>${l}</span>`).join("")}</div>
      <div class="cmap" style="height:${H}px">
        <svg class="cmap-lines" aria-hidden="true"></svg>
        ${(m.edges || []).filter((e) => e[2]).map(([a, b, l]) => {
          const p = pos[a], q = pos[b];
          return `<span class="cmap-el" style="left:${(p.x + q.x) / 2}%;top:${(p.y + q.y) / 2}px">${fmt(l)}</span>`;
        }).join("")}
        ${m.nodes.map((n) => `<button type="button" class="cnode ${n.kind}" data-n="${esc(n.id)}" style="left:${n.x}%;top:${n.row * ROW + ROW / 2}px">
          <span class="cl">${fmt(n.label)}</span>${n.sub ? `<span class="cs">${fmt(n.sub)}</span>` : ""}</button>`).join("")}
      </div>
      <div id="nodeInfo" class="card small muted">노드를 누르면 설명이 나옵니다.</div>
      ${m.summary ? `<article class="card sec"><div class="nlabel">한 장 요약</div><div class="body">${paras(m.summary)}</div></article>` : ""}`;
    // 선은 실제 픽셀 좌표로 그린다 (화살촉이 찌그러지지 않게). 화면 폭이 바뀌면 다시 그린다.
    const svg = $(".cmap-lines", body);
    const drawLines = () => {
      if (!svg.isConnected) { redraw.delete(drawLines); return; }
      const W = svg.parentElement.clientWidth;
      svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
      const hl = new Set([...svg.querySelectorAll("line.hl")].map((l) => l.dataset.e));
      svg.innerHTML = `<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="9" markerHeight="9" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" style="fill:var(--muted)"/></marker></defs>`
        + (m.edges || []).map(([a, b]) => {
          const p = pos[a], q = pos[b];
          const x1 = (p.x / 100) * W, x2 = (q.x / 100) * W;
          // 노드 위·아래 가장자리에서 끝나도록 줄인다 (노드 높이 약 54px)
          const s = Math.sign(q.y - p.y) * 28;
          const e = `${a}|${b}`;
          return `<line class="${hl.has(e) ? "hl" : ""}" data-e="${esc(e)}" x1="${x1}" y1="${p.y + s}" x2="${x2}" y2="${q.y - s}" marker-end="url(#ah)"/>`;
        }).join("");
    };
    drawLines();
    redraw.add(drawLines);
    const info = $("#nodeInfo");
    body.querySelectorAll(".cnode").forEach((b) => b.addEventListener("click", () => {
      const n = m.nodes.find((x) => x.id === b.dataset.n);
      body.querySelectorAll(".cnode").forEach((x) => x.classList.toggle("sel", x === b));
      body.querySelectorAll(".cmap-lines line").forEach((ln) => ln.classList.toggle("hl", ln.dataset.e.split("|").includes(n.id)));
      const goto = n.unit && n.unit !== u.id ? `<a class="btn small" style="margin-top:8px" href="#/u/${esc(n.unit)}">${esc(n.unitLabel || "그 단원으로")} →</a>` : "";
      const root = n.root ? `<a class="btn ghost small" style="margin-top:8px" href="#/u/${esc(u.id)}/roots" data-scroll="${esc(n.root)}">개념 설명 보기 →</a>` : "";
      info.classList.remove("muted");
      info.innerHTML = `<b>${fmt(n.label)}</b> <span class="pill ${n.kind === "core" ? "" : "gray"}">${kinds[n.kind]}</span><div style="margin-top:6px">${fmt(n.desc || "")}</div>${root} ${goto}`;
    }));
  }

  // ---------- 인터랙티브 그래프 ----------
  // 캔버스 좌표계: 수학 좌표 (x, y) → 화면. 색은 CSS 변수(밝은·어두운 화면)를 따른다.
  function makePlot(el, { xmin, xmax, ymin, ymax, ratio = 0.72, xstep = 1, ystep = 1, xlabels, ylabels }) {
    const cv = document.createElement("canvas");
    cv.className = "plot";
    el.appendChild(cv);
    const P = { xmin, xmax, ymin, ymax, cv };
    const fit = () => {
      const w = Math.min(innerW(cv.parentElement) || 320, 640);
      const h = Math.round(w * ratio);
      const dpr = window.devicePixelRatio || 1;
      cv.width = w * dpr; cv.height = h * dpr; cv.style.width = `${w}px`; cv.style.height = `${h}px`;
      P.w = w; P.h = h; P.ctx = cv.getContext("2d"); P.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    fit();
    P.X = (x) => ((x - P.xmin) / (P.xmax - P.xmin)) * P.w;
    P.Y = (y) => P.h - ((y - P.ymin) / (P.ymax - P.ymin)) * P.h;
    P.clear = () => {
      const c = P.ctx;
      c.clearRect(0, 0, P.w, P.h);
      c.lineWidth = 1; c.strokeStyle = cssVar("--line"); c.fillStyle = cssVar("--muted"); c.font = "11px Pretendard, sans-serif";
      for (let x = Math.ceil(P.xmin / xstep) * xstep; x <= P.xmax + 1e-9; x += xstep) {
        c.beginPath(); c.moveTo(P.X(x), 0); c.lineTo(P.X(x), P.h); c.stroke();
      }
      for (let y = Math.ceil(P.ymin / ystep) * ystep; y <= P.ymax + 1e-9; y += ystep) {
        c.beginPath(); c.moveTo(0, P.Y(y)); c.lineTo(P.w, P.Y(y)); c.stroke();
      }
      c.strokeStyle = cssVar("--muted"); c.lineWidth = 1.4;
      if (P.ymin <= 0 && P.ymax >= 0) { c.beginPath(); c.moveTo(0, P.Y(0)); c.lineTo(P.w, P.Y(0)); c.stroke(); }
      if (P.xmin <= 0 && P.xmax >= 0) { c.beginPath(); c.moveTo(P.X(0), 0); c.lineTo(P.X(0), P.h); c.stroke(); }
      const y0 = Math.min(Math.max(P.Y(0), 12), P.h - 4);
      const x0 = Math.min(Math.max(P.X(0), 2), P.w - 24);
      (xlabels || []).forEach((x) => c.fillText(String(x), P.X(x) + 2, y0 + (P.Y(0) > P.h - 14 ? -4 : 12)));
      (ylabels || []).forEach((y) => c.fillText(String(y), x0 + 3, P.Y(y) - 3));
    };
    P.fn = (f, color, width = 2.5, from = P.xmin, to = P.xmax) => {
      const c = P.ctx; c.strokeStyle = color; c.lineWidth = width; c.beginPath();
      let pen = false;
      const N = 400;
      for (let i = 0; i <= N; i++) {
        const x = from + ((to - from) * i) / N;
        const y = f(x);
        if (!Number.isFinite(y) || y > P.ymax + (P.ymax - P.ymin) || y < P.ymin - (P.ymax - P.ymin)) { pen = false; continue; }
        pen ? c.lineTo(P.X(x), P.Y(y)) : c.moveTo(P.X(x), P.Y(y));
        pen = true;
      }
      c.stroke();
    };
    P.hline = (y, color, dash = [5, 4]) => { const c = P.ctx; c.save(); c.setLineDash(dash); c.strokeStyle = color; c.lineWidth = 1.5; c.beginPath(); c.moveTo(0, P.Y(y)); c.lineTo(P.w, P.Y(y)); c.stroke(); c.restore(); };
    P.vline = (x, color, dash = [5, 4]) => { const c = P.ctx; c.save(); c.setLineDash(dash); c.strokeStyle = color; c.lineWidth = 1.5; c.beginPath(); c.moveTo(P.X(x), 0); c.lineTo(P.X(x), P.h); c.stroke(); c.restore(); };
    P.dot = (x, y, color, r = 5, label) => {
      const c = P.ctx; c.fillStyle = color; c.beginPath(); c.arc(P.X(x), P.Y(y), r, 0, Math.PI * 2); c.fill();
      if (label) { c.font = "600 12px Pretendard, sans-serif"; c.fillText(label, P.X(x) + 7, P.Y(y) - 7); }
    };
    P.text = (s, x, y, color, font = "600 12px Pretendard, sans-serif") => { const c = P.ctx; c.fillStyle = color; c.font = font; c.fillText(s, x, y); };
    return P;
  }
  // 슬라이더 한 줄: 라벨 · 값 표시
  function slider(el, { label, min, max, step, value, show = (v) => v }) {
    const row = document.createElement("label");
    row.className = "sl";
    row.innerHTML = `<span class="sl-l">${label}</span><input type="range" min="${min}" max="${max}" step="${step}" value="${value}"><span class="sl-v"></span>`;
    el.appendChild(row);
    const inp = $("input", row), out = $(".sl-v", row);
    const get = () => Number(inp.value);
    const upd = () => { out.innerHTML = show(get()); };
    upd();
    return { get, on(f) { inp.addEventListener("input", () => { upd(); f(); }); }, set(v) { inp.value = v; upd(); } };
  }
  function seg(el, opts, value) {
    const box = document.createElement("div");
    box.className = "seg";
    box.innerHTML = opts.map(([v, l]) => `<button type="button" data-v="${esc(v)}" class="${String(v) === String(value) ? "on" : ""}">${fmt(l)}</button>`).join("");
    el.appendChild(box);
    let cur = value, cb = () => {};
    box.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
      cur = b.dataset.v; box.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); cb();
    }));
    return { get: () => cur, on(f) { cb = f; } };
  }
  // 패딩을 뺀 안쪽 폭 (캔버스가 상자 밖으로 넘치지 않게)
  const innerW = (el) => { const cs = getComputedStyle(el); return el.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight); };
  const readout = (el) => { const d = document.createElement("div"); d.className = "ro"; el.appendChild(d); return d; };
  const wgHead = (el, title, hint) => { el.insertAdjacentHTML("beforeend", `<div class="wg-h">📈 ${fmt(title)}</div>${hint ? `<div class="wg-hint small muted">${fmt(hint)}</div>` : ""}`); };
  const num = (v, d = 4) => { const s = Number(v).toFixed(d).replace(/\.?0+$/, ""); return s === "-0" ? "0" : s; };
  const frac = (b, n) => (n >= 0 ? String(b ** n) : `\\frac{1}{${b ** -n}}`);
  const redraw = new Set();
  window.addEventListener("resize", () => redraw.forEach((f) => f()));

  const WIDGETS = {
    // 곱한 개수 세기: a^m·a^n, a^m÷a^n, (a^m)^n
    "count-factors"(el, cfg) {
      wgHead(el, cfg.title || "곱한 개수를 세어 보기", "지수법칙은 'a 가 몇 개 곱해졌나'를 세는 것뿐입니다.");
      const mode = seg(el, [["mul", "곱 $a^m a^n$"], ["div", "나누기 $a^m \\div a^n$"], ["pow", "거듭제곱 $(a^m)^n$"]], "mul");
      const sm = slider(el, { label: "m", min: 1, max: 6, step: 1, value: 3 });
      const sn = slider(el, { label: "n", min: 1, max: 6, step: 1, value: 2 });
      const box = readout(el);
      const chip = (cls, k) => Array.from({ length: k }, () => `<span class="fa ${cls}">a</span>`).join("");
      const draw = () => {
        const m = sm.get(), n = sn.get(), md = mode.get();
        let html = "", res = "";
        if (md === "mul") {
          html = `<div class="fa-row">(${chip("c1", m)}) × (${chip("c2", n)})</div>`;
          res = `a^{${m}}\\times a^{${n}} = a^{${m}+${n}} = a^{${m + n}}`;
        } else if (md === "div") {
          const k = Math.min(m, n);
          const top = chip("c1 x", k) + chip("c1", m - k), bot = chip("c2 x", k) + chip("c2", n - k);
          html = `<div class="fa-frac"><div>${top}</div><div class="fa-bar"></div><div>${bot || "1"}</div></div>
            <div class="small muted">위아래에서 같은 개수(${k}개)를 지우면 ${m > n ? `위에 ${m - n}개` : m < n ? `아래에 ${n - m}개` : "아무것도 안"} 남습니다.</div>`;
          res = `a^{${m}}\\div a^{${n}} = a^{${m}-${n}} = a^{${m - n}}` + (m < n ? ` = \\frac{1}{a^{${n - m}}}` : m === n ? " = 1" : "");
        } else {
          html = `<div class="fa-row">${Array.from({ length: n }, () => `(${chip("c1", m)})`).join(" ")}</div>
            <div class="small muted">${tex(`a^{${m}}`)} 묶음이 ${n}개 → a 는 ${m}×${n}개</div>`;
          res = `(a^{${m}})^{${n}} = a^{${m}\\times ${n}} = a^{${m * n}}`;
        }
        box.innerHTML = html + `<div class="ro-eq">${tex(res, true)}</div>`;
      };
      mode.on(draw); sm.on(draw); sn.on(draw); draw();
    },
    // 지수 사다리: 한 칸 내려갈 때마다 ÷a
    "power-ladder"(el, cfg) {
      wgHead(el, cfg.title || "지수 사다리", "지수가 1 줄 때마다 밑으로 한 번 나눕니다. 그 규칙을 0 과 음수까지 그대로 이어 가 보세요.");
      const base = seg(el, [[2, "밑 2"], [3, "밑 3"], [10, "밑 10"]], cfg.base || 2);
      const sn = slider(el, { label: "지수 n", min: -4, max: 4, step: 1, value: 3 });
      const box = readout(el);
      const draw = () => {
        const b = Number(base.get()), n = sn.get();
        const rows = [];
        for (let k = 4; k >= -4; k--) {
          rows.push(`<div class="lad ${k === n ? "on" : ""} ${k < 1 ? "ext" : ""}"><span>${tex(`${b}^{${k}}`)}</span><span>${tex(frac(b, k))}</span></div>`);
          if (k > -4) rows.push(`<div class="lad-arrow">÷${b}</div>`);
        }
        box.innerHTML = `<div class="ladder">${rows.join("")}</div>
          <div class="ro-eq">${tex(`${b}^{${n}} = ${frac(b, n)}`, true)}</div>
          <div class="small muted">${fmt(n === 0 ? `$${b}^1 = ${b}$ 에서 한 번 더 ÷${b} → 1. '0번 곱함'은 0 이 아니라 '곱셈의 출발점' 1 입니다.` : n < 0 ? `음수 지수는 '부호가 음수'가 아니라 ÷${b} 를 ${-n}번 더 한 것, 곧 역수입니다.` : `${b} 를 ${n}번 곱한 값`)}</div>`;
      };
      base.on(draw); sn.on(draw); draw();
    },
    // y = x^n 과 y = a 의 교점 = a 의 실수인 n제곱근
    "root-count"(el, cfg) {
      wgHead(el, cfg.title || "a 의 n제곱근은 몇 개?", "$y=x^n$ 과 가로선 $y=a$ 가 만나는 점의 x 좌표가 '실수인 n제곱근'입니다.");
      const P = makePlot(el, { xmin: -3, xmax: 3, ymin: -10, ymax: 10, ratio: 0.8, xstep: 1, ystep: 2, xlabels: [-2, -1, 1, 2], ylabels: [-8, -4, 4, 8] });
      const sn = slider(el, { label: "n", min: 2, max: 6, step: 1, value: cfg.n || 3, show: (v) => `${v} (${v % 2 ? "홀수" : "짝수"})` });
      const sa = slider(el, { label: "a", min: -9, max: 9, step: 0.5, value: cfg.a ?? 8 });
      const box = readout(el);
      const draw = () => {
        const n = sn.get(), a = sa.get();
        P.clear();
        P.fn((x) => x ** n, cssVar("--accent"));
        P.hline(a, cssVar("--warn"), []);
        const r = Math.abs(a) ** (1 / n);
        let roots;
        if (n % 2) roots = [Math.sign(a) * r];
        else roots = a > 0 ? [-r, r] : a === 0 ? [0] : [];
        roots.forEach((x) => { P.vline(x, cssVar("--good")); P.dot(x, a, cssVar("--good"), 6, num(x, 3)); });
        P.text(`y = x^${n}`, P.X(-2.9), P.h - 8, cssVar("--accent"));
        P.text(`y = ${a}`, 6, P.Y(a) > 24 ? P.Y(a) - 6 : P.Y(a) + 16, cssVar("--warn"));
        const sym = n % 2 ? `\\sqrt[${n}]{${a}} = ${num(roots[0], 4)}` : a > 0 ? `\\pm\\sqrt[${n}]{${a}} = \\pm ${num(r, 4)}` : a === 0 ? "0" : "";
        box.innerHTML = `<div><b>실수인 ${n}제곱근: ${roots.length}개</b>${sym ? ` &nbsp; ${tex(sym)}` : ""}</div>
          <div class="small muted">${n % 2 ? "홀수 n: 그래프가 아래에서 위로 한 번 지나가므로 어떤 a 든 꼭 한 번 만납니다." : a > 0 ? "짝수 n, a > 0: 그래프가 U 모양이라 양쪽에서 두 번 만납니다 (서로 부호만 반대)." : a === 0 ? "a = 0: 원점에서 한 번만 만납니다." : "짝수 n, a < 0: x^n 은 0 이상이라 가로선과 만나지 않습니다. 실수 범위에는 없습니다."}</div>`;
      };
      redraw.add(draw);
      sn.on(draw); sa.on(draw); draw();
    },
    // 2^√2 : 유리수 지수 근삿값이 한 값으로 모인다
    "real-exponent"(el, cfg) {
      const b = cfg.base || 2;
      wgHead(el, cfg.title || `$${b}^{\\sqrt2}$ 은 어떻게 정할까?`, "√2 의 자릿수를 하나씩 늘려 가며 2^(유리수) 를 계산해 보세요. 값이 한 곳으로 모입니다.");
      const P = makePlot(el, { xmin: 0.9, xmax: 1.6, ymin: 1.7, ymax: 3.1, ratio: 0.62, xstep: 0.1, ystep: 0.2, xlabels: [1, 1.2, 1.4], ylabels: [2, 2.4, 2.8] });
      const sk = slider(el, { label: "자릿수", min: 0, max: 6, step: 1, value: 2, show: (v) => `소수 ${v}자리` });
      const box = readout(el);
      const R = Math.SQRT2;
      const draw = () => {
        const k = sk.get();
        P.clear();
        P.fn((x) => b ** x, cssVar("--line"), 2);
        P.fn((x) => b ** x, cssVar("--accent"), 3, 0.9, Math.floor(R * 10 ** k) / 10 ** k);
        const rows = [];
        for (let j = 0; j <= k; j++) {
          const r = Math.floor(R * 10 ** j) / 10 ** j;
          P.dot(r, b ** r, j === k ? cssVar("--bad") : cssVar("--muted"), j === k ? 6 : 3.5);
          rows.push(`<tr class="${j === k ? "on" : ""}"><td>${tex(`${b}^{${r.toFixed(j)}}`)}</td><td>${(b ** r).toFixed(6)}</td></tr>`);
        }
        P.vline(R, cssVar("--good"));
        P.text("x = √2", P.X(R) + 4, 14, cssVar("--good"));
        box.innerHTML = `<div class="tbl-wrap"><table class="mini"><thead><tr><th>유리수 지수</th><th>값</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>
          <div class="small" style="margin-top:6px">→ 이 값들이 다가가는 수 <b>${(b ** R).toFixed(6)}…</b> 을 ${tex(`${b}^{\\sqrt2}`)} 로 정합니다.</div>`;
      };
      redraw.add(draw);
      sk.on(draw); draw();
    },
    // 지수 눈금과 값 눈금을 나란히: log 는 아래 눈금의 수를 위 눈금으로 옮긴다
    "log-scale"(el, cfg) {
      const b = cfg.base || 2;
      wgHead(el, cfg.title || "두 개의 눈금", `위는 '지수' 눈금(일정한 간격), 아래는 '값' 눈금입니다. 같은 자리에 있는 두 수가 $${b}^x = N$, 곧 $x = \\log_{${b}} N$ 입니다.`);
      const cv = document.createElement("canvas"); cv.className = "plot"; el.appendChild(cv);
      const sx = slider(el, { label: "x", min: -3, max: 6, step: 0.1, value: cfg.x ?? 3.3, show: (v) => num(v, 1) });
      const box = readout(el);
      const draw = () => {
        const w = Math.min(innerW(cv.parentElement) || 320, 640), h = 130, dpr = window.devicePixelRatio || 1;
        cv.width = w * dpr; cv.height = h * dpr; cv.style.width = `${w}px`; cv.style.height = `${h}px`;
        const c = cv.getContext("2d"); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, w, h);
        const X = (x) => 16 + ((x + 3) / 9) * (w - 32);
        const x = sx.get(), N = b ** x;
        c.strokeStyle = cssVar("--muted"); c.lineWidth = 1.5;
        [40, 92].forEach((y) => { c.beginPath(); c.moveTo(X(-3), y); c.lineTo(X(6), y); c.stroke(); });
        c.font = "11px Pretendard, sans-serif"; c.fillStyle = cssVar("--muted");
        c.fillText("지수 x", 0, 14); c.fillText(`값 ${b}^x`, 0, 124);
        for (let k = -3; k <= 6; k++) {
          c.strokeStyle = cssVar("--line"); c.beginPath(); c.moveTo(X(k), 40); c.lineTo(X(k), 92); c.stroke();
          c.fillStyle = cssVar("--text"); c.textAlign = "center";
          c.fillText(String(k), X(k), 32);
          c.fillText(k >= 0 ? String(b ** k) : `1/${b ** -k}`, X(k), 108);
        }
        c.textAlign = "left";
        c.strokeStyle = cssVar("--bad"); c.lineWidth = 2.5; c.beginPath(); c.moveTo(X(x), 36); c.lineTo(X(x), 96); c.stroke();
        c.fillStyle = cssVar("--bad"); c.beginPath(); c.arc(X(x), 40, 5, 0, 7); c.fill(); c.beginPath(); c.arc(X(x), 92, 5, 0, 7); c.fill();
        box.innerHTML = `<div class="ro-eq">${tex(`${b}^{${num(x, 1)}} \\approx ${num(N, N < 1 ? 4 : 2)} \\iff \\log_{${b}} ${num(N, N < 1 ? 4 : 2)} \\approx ${num(x, 1)}`, true)}</div>
          <div class="small muted">위 눈금에서 한 칸(+1) 가면 아래 값은 ×${b}. 더하기(위)가 곱하기(아래)로 바뀌는 것이 로그의 핵심입니다.</div>`;
      };
      redraw.add(draw);
      sx.on(draw); draw();
    },
    // 계산자: log a + log b = log ab 를 길이로
    "slide-rule"(el, cfg) {
      wgHead(el, cfg.title || "계산자로 곱하기", "아래 자(D)의 a 에 위 자(C)의 1 을 맞추면, 위 자의 b 바로 아래에 a×b 가 있습니다. 길이(로그)를 더했을 뿐인데 곱이 나옵니다.");
      const cv = document.createElement("canvas"); cv.className = "plot"; el.appendChild(cv);
      const sa = slider(el, { label: "a", min: 1, max: 9.9, step: 0.1, value: 2, show: (v) => num(v, 1) });
      const sb = slider(el, { label: "b", min: 1, max: 9.9, step: 0.1, value: 3, show: (v) => num(v, 1) });
      const box = readout(el);
      const draw = () => {
        const w = Math.min(innerW(cv.parentElement) || 320, 640), h = 150, dpr = window.devicePixelRatio || 1;
        cv.width = w * dpr; cv.height = h * dpr; cv.style.width = `${w}px`; cv.style.height = `${h}px`;
        const c = cv.getContext("2d"); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, w, h);
        const L = (w - 24) / 2;            // log 1 ~ log 10 의 길이 (D 자는 1 ~ 100 까지)
        const X = (v) => 12 + Math.log10(v) * L;
        let a = sa.get(), bb = sb.get();
        const off = Math.log10(a) * L;
        const scale = (y, from, to, shift, up) => {
          c.fillStyle = cssVar("--card"); c.strokeStyle = cssVar("--muted"); c.lineWidth = 1;
          c.fillRect(12 + shift, y, (Math.log10(to) - Math.log10(from)) * L, 30); c.strokeRect(12 + shift, y, (Math.log10(to) - Math.log10(from)) * L, 30);
          c.fillStyle = cssVar("--text"); c.font = "10px Pretendard, sans-serif"; c.textAlign = "center";
          for (let v = from; v <= to + 1e-9; v += v < 10 ? 1 : 10) {
            const xx = 12 + shift + Math.log10(v / from) * L;
            c.beginPath(); c.moveTo(xx, up ? y + 30 : y); c.lineTo(xx, up ? y + 18 : y + 12); c.stroke();
            const r = Math.round(v / from);   // 칸이 좁은 7, 9, 40, 60… 은 눈금만
            if (r < 10 ? [1, 2, 3, 4, 5, 6, 8].includes(r) : [10, 20, 30, 50, 100].includes(r)) c.fillText(String(v), xx, up ? y + 13 : y + 25);
          }
          c.textAlign = "left";
        };
        scale(36, 1, 10, off, true);     // C 자 (위, 움직임)
        scale(66, 1, 100, 0, false);     // D 자 (아래, 고정)
        c.fillStyle = cssVar("--muted"); c.font = "11px Pretendard, sans-serif"; c.fillText("C", 0, 56); c.fillText("D", 0, 86);
        const prod = a * bb;
        const cx = X(prod);
        c.strokeStyle = cssVar("--bad"); c.lineWidth = 2; c.beginPath(); c.moveTo(cx, 28); c.lineTo(cx, 104); c.stroke();
        c.strokeStyle = cssVar("--accent"); c.lineWidth = 4;
        c.beginPath(); c.moveTo(12, 122); c.lineTo(12 + off, 122); c.stroke();
        c.strokeStyle = cssVar("--good");
        c.beginPath(); c.moveTo(12 + off, 132); c.lineTo(cx, 132); c.stroke();
        c.font = "600 11px Pretendard, sans-serif";
        c.fillStyle = cssVar("--accent"); c.fillText("log a", 14, 117);
        c.fillStyle = cssVar("--good"); c.fillText("log b", 14 + off, 146);
        box.innerHTML = `<div class="ro-eq">${tex(`\\log ${num(a, 1)} + \\log ${num(bb, 1)} = \\log(${num(a, 1)}\\times${num(bb, 1)}) = \\log ${num(prod, 2)}`, true)}</div>
          <div class="small muted">빨간 선 아래 D 자 눈금이 ${num(prod, 2)} 입니다. 1620년대부터 1970년대 전자계산기가 나오기 전까지 공학자들이 이렇게 곱셈을 했습니다.</div>`;
      };
      redraw.add(draw);
      sa.on(draw); sb.on(draw); draw();
    },
    // 밑 변환: log2 x 와 log10 x 는 언제나 같은 비율
    "change-base"(el, cfg) {
      wgHead(el, cfg.title || "밑이 달라도 모양은 같다", "$y=\\log_2 x$ 와 $y=\\log_{10} x$ 를 같은 x 에서 비교해 보세요. 비율이 언제나 같습니다.");
      const P = makePlot(el, { xmin: 0, xmax: 20, ymin: -2.5, ymax: 5, ratio: 0.7, xstep: 2, ystep: 1, xlabels: [2, 4, 8, 16], ylabels: [-2, 1, 2, 3, 4] });
      const sx = slider(el, { label: "x", min: 0.2, max: 20, step: 0.1, value: 8, show: (v) => num(v, 1) });
      const box = readout(el);
      const draw = () => {
        const x = sx.get();
        P.clear();
        P.fn((t) => Math.log2(t), cssVar("--accent"), 2.5, 0.01);
        P.fn((t) => Math.log10(t), cssVar("--good"), 2.5, 0.01);
        P.vline(x, cssVar("--muted"));
        P.dot(x, Math.log2(x), cssVar("--accent"), 5);
        P.dot(x, Math.log10(x), cssVar("--good"), 5);
        P.text("y = log₂x", P.X(13), P.Y(Math.log2(13)) - 8, cssVar("--accent"));
        P.text("y = log₁₀x", P.X(13), P.Y(Math.log10(13)) + 16, cssVar("--good"));
        const l2 = Math.log2(x), l10 = Math.log10(x);
        box.innerHTML = Math.abs(x - 1) < 0.05
          ? `<div class="small">${fmt("x = 1 에서는 두 값이 모두 0 입니다 (어떤 밑이든 $\\log 1 = 0$). 다른 x 로 옮겨 보세요.")}</div>`
          : `<div class="ro-eq">${tex(`\\frac{\\log_2 ${num(x, 1)}}{\\log_{10} ${num(x, 1)}} = \\frac{${num(l2, 4)}}{${num(l10, 4)}} \\approx ${num(l2 / l10, 4)}`, true)}</div>
          <div class="small muted">x 를 어디로 옮겨도 ≈ 3.3219 = ${tex("\\frac{1}{\\log_{10}2}")}. 밑을 바꾸는 것은 그래프를 세로로 일정하게 늘이거나 줄이는 것뿐입니다.</div>`;
      };
      redraw.add(draw);
      sx.on(draw); draw();
    },
    // 자릿수: N = b^k 의 자릿수 = floor(k·log10 b) + 1
    "digits"(el, cfg) {
      wgHead(el, cfg.title || "몇 자리 수일까?", "상용로그의 정수 부분이 n 이면 그 수는 n+1 자리입니다. 정확한 값과 비교해 보세요.");
      const base = seg(el, [[2, "밑 2"], [3, "밑 3"], [7, "밑 7"]], cfg.base || 2);
      const sk = slider(el, { label: "k", min: 1, max: 200, step: 1, value: cfg.k || 100 });
      const box = readout(el);
      const draw = () => {
        const b = Number(base.get()), k = sk.get();
        const exact = (BigInt(b) ** BigInt(k)).toString();
        const lg = k * Math.log10(b);
        const shown = exact.length > 36 ? `${exact.slice(0, 16)}…${exact.slice(-8)}` : exact;
        box.innerHTML = `<div class="ro-eq">${tex(`\\log ${b}^{${k}} = ${k}\\log ${b} \\approx ${k}\\times${Math.log10(b).toFixed(4)} = ${lg.toFixed(2)}`, true)}</div>
          <div>${tex(`10^{${Math.floor(lg)}} \\le ${b}^{${k}} < 10^{${Math.floor(lg) + 1}}`)} → <b>${Math.floor(lg) + 1}자리</b></div>
          <div class="small muted" style="margin-top:6px">실제 값: <span class="mono">${shown}</span> (${exact.length}자리)</div>`;
      };
      base.on(draw); sk.on(draw); draw();
    },
  };

  // ---------- 질문하기 ----------
  function renderAsk(params) {
    const ref = params.get("ref") || "";
    const url = feedbackUrl(ref);
    view.innerHTML = `<h2>질문하기</h2>
      <div class="card">
        <p>이해가 안 되는 설명, 학교에서 배운 것과 달라 보이는 내용, 설명이 더 필요한 개념을 올려 주세요.</p>
        <ul class="small"><li>교과서·프린트 사진을 올려도 됩니다.</li><li>'어디까지는 이해했고 어디서부터 막혔는지' 적어 주면 그 부분을 보충합니다.</li></ul>
        ${ref ? `<p class="small muted">자동으로 채워지는 정보: <b>${esc(ref)}</b></p>` : ""}
        ${url ? `<a class="btn" style="width:100%" href="${esc(url)}" target="_blank" rel="noopener">올리기 화면 열기</a>`
          : `<div class="notice">아직 올리기 채널이 연결되지 않았습니다 (data/site-config.json).</div>`}
      </div>`;
  }

  // ---------- 공통 클릭 ----------
  document.addEventListener("click", (e) => {
    const q = e.target.closest(".drill-q");
    if (q) { const a = q.nextElementSibling; a.hidden = !a.hidden; q.classList.toggle("open", !a.hidden); return; }
    const b = e.target.closest(".rate button");
    if (b && !b.disabled) {
      const bar = b.closest(".rate");
      sendRating(bar.dataset.cat, bar.dataset.item, /더/.test(b.dataset.v) ? "요청" : "평가", b.dataset.v);
      bar.querySelectorAll("button").forEach((x) => { x.disabled = true; });
      b.classList.add("on");
      bar.querySelector(".sent").hidden = false;
      return;
    }
    const sc = e.target.closest("[data-scroll]");
    if (sc) pendingScroll = sc.dataset.scroll;
  }, true);
  let pendingScroll = "";

  // ---------- 라우터 ----------
  async function route() {
    const raw = location.hash.replace(/^#/, "") || "/";
    const [path, qs] = raw.split("?");
    const parts = path.split("/").filter(Boolean);
    try {
      const idx = await loadIndex();
      $("#builtAt").textContent = idx.updated ? `내용 업데이트 ${idx.updated}` : "";
      if (parts[0] === "u" && parts[1]) await renderUnit(parts[1], parts[2] || "why");
      else if (parts[0] === "ask") renderAsk(new URLSearchParams(qs || ""));
      else await renderHome(idx);
    } catch (err) {
      view.innerHTML = `<p class="notice">내용을 불러오지 못했습니다. 잠시 뒤 새로고침해 주세요.<br><span class="small">${esc(err.message)}</span></p>`;
    }
    const target = pendingScroll && document.getElementById(pendingScroll);
    pendingScroll = "";
    if (target) target.scrollIntoView({ block: "start" }); else window.scrollTo(0, 0);
  }
  let started = false;
  function start() {
    window.SITE_CONFIG = bundle ? bundle.config : window.SITE_CONFIG;
    $("#lock").hidden = true;
    $("#app").hidden = false;
    $("#lockBtn").hidden = !enc;
    if (!started) { window.addEventListener("hashchange", route); started = true; }
    route();
  }
  async function boot() {
    $("#lockForm").addEventListener("submit", unlock);
    $("#lockBtn").addEventListener("click", lockNow);
    const r = await fetch("data/content.enc", { cache: "no-cache" }).catch(() => null);
    if (r && r.ok) {
      enc = await r.json();
      if (await tryStoredKey()) start(); else showLock("");
    } else {
      window.SITE_CONFIG = await getJSON("data/site-config.json").catch(() => ({}));
      start();
    }
  }
  boot();
})();
