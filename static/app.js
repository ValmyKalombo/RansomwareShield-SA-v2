/* RansomwareShield-SA v3.1.0 - CSP-safe front end (no inline scripts or styles) */
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const csrf = () => ($('meta[name="csrf-token"]') || {}).content || '';
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const LEVEL_COLOUR = {strong:'#16a34a', good:'#6f2cff', developing:'#d97706', weak:'#ea580c', critical:'#dc2626'};

  function md(text) {
    const lines = esc(text).split('\n'); let html = '', list = null;
    const inline = t => t.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/\*(.+?)\*/g, '<i>$1</i>').replace(/`(.+?)`/g, '<code>$1</code>');
    const close = () => { if (list) { html += `</${list}>`; list = null; } };
    for (const raw of lines) {
      const l = raw.trim();
      let m;
      if ((m = l.match(/^[-*] (.*)/))) { if (list !== 'ul') { close(); html += '<ul>'; list = 'ul'; } html += `<li>${inline(m[1])}</li>`; }
      else if ((m = l.match(/^\d+\. (.*)/))) { if (list !== 'ol') { close(); html += '<ol>'; list = 'ol'; } html += `<li>${inline(m[1])}</li>`; }
      else if (!l) { close(); }
      else { close(); html += `<p>${inline(l)}</p>`; }
    }
    close(); return html;
  }

  document.addEventListener('DOMContentLoaded', () => {
    /* --- basics --- */
    $$('[data-width]').forEach(el => requestAnimationFrame(() => { el.style.width = Math.max(0, Math.min(100, +el.dataset.width || 0)) + '%'; }));
    $('[data-menu]')?.addEventListener('click', () => document.body.classList.toggle('menu-open'));
    $$('[data-toggle-pw]').forEach(b => b.addEventListener('click', () => {
      const i = b.parentElement.querySelector('input'); i.type = i.type === 'password' ? 'text' : 'password'; b.textContent = i.type === 'password' ? 'Show' : 'Hide';
    }));
    const pw = $('[data-strength]'), meter = $('.strength');
    if (pw && meter) pw.addEventListener('input', () => {
      const v = pw.value; let s = 0;
      if (v.length >= 12) s++; if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++; if (/\d/.test(v)) s++; if (/[^A-Za-z0-9]/.test(v)) s++;
      const lab = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'], col = ['#dc2626', '#ea580c', '#d97706', '#2563eb', '#16a34a'];
      meter.querySelector('i').style.width = (20 + s * 30) + 'px'; meter.querySelector('i').style.background = col[s]; meter.querySelector('span').textContent = lab[s];
    });
    $$('form').forEach(f => f.addEventListener('submit', e => {
      if (f.dataset.confirm && !confirm(f.dataset.confirm)) { e.preventDefault(); return; }
      if (f.matches('[data-ai-form],[data-scan-form]')) return;
      setTimeout(() => $$('button[type=submit],input[type=submit],button:not([type])', f).forEach(b => b.disabled = true), 10);
    }));
    $$('[data-copy-btn]').forEach(b => b.addEventListener('click', async () => {
      const inp = b.parentElement.querySelector('[data-copy]'); inp.select();
      try { await navigator.clipboard.writeText(inp.value); } catch { document.execCommand('copy'); }
      b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy', 1800);
    }));
    $$('[data-filter]').forEach(inp => inp.addEventListener('input', () => {
      const q = inp.value.toLowerCase(); $$(inp.dataset.filter + ' [data-row]').forEach(r => r.hidden = !r.textContent.toLowerCase().includes(q));
    }));

    /* --- gauge --- */
    const gauge = $('[data-gauge]');
    if (gauge) {
      const v = +gauge.dataset.gauge || 0, arc = $('.g-arc', gauge);
      arc.style.stroke = LEVEL_COLOUR[gauge.dataset.level] || '#6f2cff';
      requestAnimationFrame(() => setTimeout(() => { arc.style.strokeDashoffset = 528 * (1 - v / 100); }, 120));
      const num = $('[data-count]', gauge); let t0 = null;
      const step = ts => { t0 = t0 || ts; const p = Math.min(1, (ts - t0) / 1300); num.textContent = (v * (1 - Math.pow(1 - p, 3))).toFixed(1) + '%'; if (p < 1) requestAnimationFrame(step); };
      requestAnimationFrame(step);
    }

    /* --- charts --- */
    const hiDpi = (c, h) => { const d = window.devicePixelRatio || 1, w = c.clientWidth || 600; c.width = w * d; c.height = h * d; const x = c.getContext('2d'); x.scale(d, d); return [x, w, h]; };
    const radar = $('#radar');
    if (radar) {
      const labels = JSON.parse(radar.dataset.labels), scores = JSON.parse(radar.dataset.scores).map(v => +v || 0);
      const [ctx, w, h] = hiDpi(radar, 380), cx = w / 2, cy = h / 2 + 4, R = Math.min(w, h) * .33, n = labels.length;
      const pt = (i, v) => { const a = -Math.PI / 2 + i * 2 * Math.PI / n; return [cx + Math.cos(a) * R * v, cy + Math.sin(a) * R * v]; };
      let t = 0;
      const draw = () => {
        t = Math.min(1, t + .04); ctx.clearRect(0, 0, w, h);
        ctx.font = '600 12px Segoe UI, Arial'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        for (let r = 1; r <= 5; r++) { ctx.beginPath(); for (let i = 0; i < n; i++) { const [x, y] = pt(i, r / 5); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); } ctx.closePath(); ctx.fillStyle = r % 2 ? '#fafbff' : '#fff'; ctx.fill(); ctx.strokeStyle = '#e3e6f0'; ctx.stroke(); }
        labels.forEach((l, i) => { let [x, y] = pt(i, 1); ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(x, y); ctx.strokeStyle = '#e3e6f0'; ctx.stroke(); [x, y] = pt(i, 1.2); ctx.fillStyle = '#1c1f33'; ctx.fillText(l, x, y - 6); ctx.fillStyle = '#6f2cff'; ctx.fillText(scores[i] + '%', x, y + 9); });
        ctx.beginPath(); scores.forEach((s, i) => { const [x, y] = pt(i, s / 100 * t); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.closePath();
        const g = ctx.createLinearGradient(cx - R, cy - R, cx + R, cy + R); g.addColorStop(0, 'rgba(111,44,255,.32)'); g.addColorStop(1, 'rgba(49,200,255,.28)');
        ctx.fillStyle = g; ctx.fill(); ctx.lineWidth = 2.5; ctx.strokeStyle = '#6f2cff'; ctx.stroke();
        scores.forEach((s, i) => { const [x, y] = pt(i, s / 100 * t); ctx.beginPath(); ctx.arc(x, y, 4.5, 0, 7); ctx.fillStyle = '#31c8ff'; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = '#fff'; ctx.stroke(); });
        if (t < 1) requestAnimationFrame(draw);
      };
      draw();
    }
    const trend = $('#trend-chart');
    if (trend) {
      const pts = JSON.parse(trend.dataset.points || '[]'); const [ctx, w, h] = hiDpi(trend, 230), pad = 34, iw = w - pad * 2, ih = h - pad * 2;
      ctx.font = '11px Segoe UI, Arial';
      [0, 40, 60, 75, 90, 100].forEach(v => { const y = pad + ih - ih * v / 100; ctx.strokeStyle = '#eef0f6'; ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke(); ctx.fillStyle = '#8a8fab'; ctx.fillText(v, 4, y + 4); });
      const xy = (i, v) => [pad + (pts.length === 1 ? iw / 2 : iw * i / (pts.length - 1)), pad + ih - ih * v / 100];
      if (pts.length > 1) { const g = ctx.createLinearGradient(0, pad, 0, h); g.addColorStop(0, 'rgba(111,44,255,.25)'); g.addColorStop(1, 'rgba(111,44,255,0)'); ctx.beginPath(); pts.forEach((p, i) => { const [x, y] = xy(i, p.score); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.lineTo(xy(pts.length - 1, 0)[0], pad + ih); ctx.lineTo(xy(0, 0)[0], pad + ih); ctx.fillStyle = g; ctx.fill(); ctx.beginPath(); pts.forEach((p, i) => { const [x, y] = xy(i, p.score); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.strokeStyle = '#6f2cff'; ctx.lineWidth = 3; ctx.stroke(); }
      ctx.textAlign = 'center'; pts.forEach((p, i) => { const [x, y] = xy(i, p.score); ctx.beginPath(); ctx.arc(x, y, 5, 0, 7); ctx.fillStyle = '#31c8ff'; ctx.fill(); ctx.fillStyle = '#1c1f33'; ctx.fillText(p.score + '%', x, y - 12); ctx.fillStyle = '#8a8fab'; ctx.fillText(p.label, x, h - 6); });
    }

    /* --- ShieldAI --- */
    const panel = $('[data-ai-panel]'), body = $('[data-ai-body]'), form = $('[data-ai-form]'), engineLabel = $('[data-ai-engine]');
    const history = []; let busy = false;
    const openAI = () => { if (!panel) return; panel.classList.add('open'); panel.setAttribute('aria-hidden', 'false'); setTimeout(() => form?.querySelector('input').focus(), 200); };
    const closeAI = () => { panel?.classList.remove('open'); panel?.setAttribute('aria-hidden', 'true'); };
    $('[data-ai-open]')?.addEventListener('click', () => panel.classList.contains('open') ? closeAI() : openAI());
    $('[data-ai-close]')?.addEventListener('click', closeAI);
    const scrollDown = () => { body.scrollTop = body.scrollHeight; };
    const bubble = (cls, html) => { const d = document.createElement('div'); d.className = 'msg ' + cls; d.innerHTML = html; body.append(d); scrollDown(); return d; };
    const STAGES = ['Reading your question', 'Checking your latest assessment', 'Correlating with NIST CSF 2.0', 'Reviewing ransomware defence guidance', 'Drafting a clear answer'];

    async function ask(q) {
      q = (q || '').trim(); if (!q || busy || !body) return;
      busy = true; openAI(); $('[data-chips]')?.remove();
      bubble('user', `<p>${esc(q)}</p>`);
      const think = bubble('bot thinking', '<div class="dots"><i></i><i></i><i></i></div><small>Reading your question</small>');
      let si = 0; const stageTimer = setInterval(() => { si = Math.min(STAGES.length - 1, si + 1); think.querySelector('small').textContent = STAGES[si]; }, 650);
      const started = Date.now(); let data;
      try {
        const r = await fetch('/ai/chat', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf()},
          body: JSON.stringify({question: q, history: history.slice(-6), page: document.querySelector('[data-page]')?.dataset.page || ''})});
        data = r.ok ? await r.json() : {answer: r.status === 429 ? 'You are sending questions quickly - please wait a moment and try again.' : 'ShieldAI could not respond right now. Please try again.'};
      } catch { data = {answer: 'ShieldAI is offline. Check your connection and try again.'}; }
      const minThink = 1100 + Math.min(1600, (data.answer || '').length * 2);
      await sleep(Math.max(0, minThink - (Date.now() - started)));
      clearInterval(stageTimer); think.remove();
      const msg = bubble('bot', ''); const tokens = (data.answer || '').split(/(\s+)/); let shown = '';
      for (let i = 0; i < tokens.length; i += 3) { shown += tokens.slice(i, i + 3).join(''); msg.innerHTML = md(shown); scrollDown(); await sleep(18); }
      if (data.engine) { msg.insertAdjacentHTML('beforeend', `<span class="engine">${esc(data.engine)}</span>`); engineLabel.textContent = data.engine + ' \u00b7 online'; }
      history.push({role: 'user', content: q}, {role: 'assistant', content: data.answer || ''});
      if (data.suggestions?.length) { const c = document.createElement('div'); c.className = 'chips'; data.suggestions.forEach(s => { const b = document.createElement('button'); b.type = 'button'; b.textContent = s; b.addEventListener('click', () => { c.remove(); ask(s); }); c.append(b); }); body.append(c); scrollDown(); }
      busy = false;
      if (data.tour) { await sleep(900); closeAI(); startTour(); }
    }
    form?.addEventListener('submit', e => { e.preventDefault(); const i = form.querySelector('input'); const q = i.value; i.value = ''; ask(q); });
    $$('[data-q]').forEach(b => b.addEventListener('click', () => ask(b.dataset.q)));
    $$('[data-ai-ask]').forEach(b => b.addEventListener('click', () => ask(b.dataset.aiAsk)));

    /* --- guided tour --- */
    const layer = $('[data-tour-layer]'), spot = $('[data-tour-spot]'), card = $('[data-tour-card]');
    let steps = [], idx = 0;
    async function startTour() {
      if (!layer) return;
      try { steps = (await (await fetch('/ai/tour')).json()).steps.filter(s => $(`[data-tour="${s.target}"]`)); } catch { return; }
      if (!steps.length) return; idx = 0;
      if (window.innerWidth < 900) document.body.classList.add('menu-open');
      layer.hidden = false; show();
    }
    function show() {
      const s = steps[idx], el = $(`[data-tour="${s.target}"]`); el.scrollIntoView({block: 'center', behavior: 'smooth'});
      setTimeout(() => {
        const r = el.getBoundingClientRect(), p = 7;
        Object.assign(spot.style, {top: (r.top - p) + 'px', left: (r.left - p) + 'px', width: (r.width + p * 2) + 'px', height: (r.height + p * 2) + 'px'});
        $('[data-tour-count]').textContent = `STEP ${idx + 1} OF ${steps.length}`; $('[data-tour-title]').textContent = s.title; $('[data-tour-text]').textContent = s.text;
        $('[data-tour-next]').textContent = idx === steps.length - 1 ? 'Finish' : 'Next'; $('[data-tour-prev]').disabled = idx === 0;
        const cw = card.offsetWidth, ch = card.offsetHeight, vw = innerWidth, vh = innerHeight;
        let left = r.right + 18, top = r.top;
        if (left + cw > vw - 12) { left = Math.max(12, Math.min(vw - cw - 12, r.left)); top = r.bottom + 16; if (top + ch > vh - 12) top = Math.max(12, r.top - ch - 16); }
        card.style.left = left + 'px'; card.style.top = Math.max(12, Math.min(vh - ch - 12, top)) + 'px';
      }, 260);
    }
    const endTour = () => { layer.hidden = true; document.body.classList.remove('menu-open'); };
    $('[data-tour-next]')?.addEventListener('click', () => { if (idx < steps.length - 1) { idx++; show(); } else endTour(); });
    $('[data-tour-prev]')?.addEventListener('click', () => { if (idx > 0) { idx--; show(); } });
    $('[data-tour-skip]')?.addEventListener('click', endTour);
    $$('[data-start-tour]').forEach(b => b.addEventListener('click', startTour));
    addEventListener('keydown', e => { if (e.key === 'Escape') { if (layer && !layer.hidden) endTour(); else closeAI(); } });
    addEventListener('resize', () => { if (layer && !layer.hidden) show(); });

    /* --- Threat Exposure scanner --- */
    const scanForm = $('[data-scan-form]');
    if (scanForm) {
      const res = $('[data-scan-results]'), grid = $('[data-check-grid]'), ring = $('[data-ring]'), arc = $('.g-arc', ring);
      const ICON = {pass: '\u2713', warn: '!', fail: '\u2715', info: 'i'};
      const LABEL = {pass: 'Healthy', warn: 'Attention', fail: 'Critical', info: 'Info'};
      $$('[data-example]').forEach(b => b.addEventListener('click', () => { scanForm.target.value = b.dataset.example; scanForm.requestSubmit(); }));
      scanForm.addEventListener('submit', async e => {
        e.preventDefault(); const target = scanForm.target.value.trim(); if (!target) return;
        const btn = $('[data-scan-btn]'); btn.disabled = true; btn.textContent = 'Scanning\u2026';
        res.hidden = false; res.className = 'scan-results is-scanning'; grid.innerHTML = ''; arc.style.strokeDashoffset = '';
        $('[data-ring-score]').textContent = '\u2026'; $('[data-ring-risk]').textContent = 'Scanning'; $('[data-ring-icon]').textContent = '';
        $('[data-scan-title]').textContent = 'Scanning external exposure\u2026'; $('[data-scan-domain]').textContent = target; $('[data-scan-summary]').textContent = 'Resolving DNS, inspecting email defences, checking HTTPS and threat intelligence.';
        ['pass', 'warn', 'fail', 'info'].forEach(k => $(`[data-c-${k}]`).textContent = `0 ${ {pass: 'healthy', warn: 'attention', fail: 'critical', info: 'info'}[k] }`);
        res.scrollIntoView({behavior: 'smooth', block: 'start'});
        let data; const t0 = Date.now();
        try { const r = await fetch('/threat-exposure/scan', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf()}, body: JSON.stringify({target})}); data = await r.json(); if (!r.ok) throw new Error(data.error || (r.status === 429 ? 'Scan limit reached - try again later.' : 'Scan failed.')); }
        catch (err) { res.className = 'scan-results'; $('[data-scan-title]').textContent = 'Scan could not run'; $('[data-scan-summary]').textContent = err.message; btn.disabled = false; btn.textContent = 'Run exposure scan'; return; }
        await sleep(Math.max(0, 1500 - (Date.now() - t0)));
        const risk = data.risk.toLowerCase(); res.className = 'scan-results r-' + risk;
        $('[data-scan-domain]').textContent = data.domain + (data.email ? ' \u00b7 ' + data.email : '');
        $('[data-scan-title]').textContent = `${data.risk} exposure`; $('[data-scan-summary]').textContent = data.summary;
        $('[data-ring-icon]').textContent = risk === 'low' ? '\u2713' : risk === 'medium' ? '!' : '\u2715'; $('[data-ring-risk]').textContent = data.risk + ' risk';
        arc.style.strokeDashoffset = 528 * (1 - data.score / 100);
        let n = 0; const iv = setInterval(() => { n = Math.min(data.score, n + 3); $('[data-ring-score]').textContent = n; if (n >= data.score) clearInterval(iv); }, 22);
        const counts = {pass: 0, warn: 0, fail: 0, info: 0}; const order = {fail: 0, warn: 1, pass: 2, info: 3};
        for (const c of [...data.checks].sort((a, b) => order[a.status] - order[b.status])) {
          const el = document.createElement('article'); el.className = 'chk ' + c.status;
          el.innerHTML = `<div class="badge">${ICON[c.status]}</div><div><h4>${esc(c.name)}<small>${esc(c.group)} \u00b7 ${LABEL[c.status]}</small></h4><p>${esc(c.detail)}</p>${c.advice ? `<p class="adv">\u2192 ${esc(c.advice)}</p>` : ''}</div>`;
          grid.append(el); await sleep(110); el.classList.add('show');
          counts[c.status]++; ['pass', 'warn', 'fail', 'info'].forEach(k => $(`[data-c-${k}]`).textContent = `${counts[k]} ${ {pass: 'healthy', warn: 'attention', fail: 'critical', info: 'info'}[k] }`);
        }
        const hist = $('[data-history]');
        if (hist) { hist.querySelector('.empty')?.parentElement.remove(); const tr = document.createElement('tr'); const sym = {low: '\u2713', medium: '!', high: '\u2715', critical: '\u2715'}[risk];
          tr.innerHTML = `<td>${esc(target.toLowerCase())}</td><td>${data.email ? 'Email' : 'Domain'}</td><td><span class="risk-pill r-${risk}">${sym} ${esc(data.risk)}</span></td><td>Just now</td>`; hist.rows[0].after(tr); }
        btn.disabled = false; btn.textContent = 'Run exposure scan';
      });
    }
  });
})();
