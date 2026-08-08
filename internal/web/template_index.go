package web

// indexHTML 是主界面。单页,四个标签:流量 / 探测 / 敲门 / 审计。
//
// 设计取舍:纯手写 SVG 画图,不引入 ECharts。pingping 那份
// echarts.min.js 有 1MB,嵌进单一二进制会让体积大出一截,而这里需要的
// 图形(时间序列折线 + 分位带、横向排行条)用几十行 SVG 就能画好,
// 而且没有外部 CDN 依赖 —— 内网部署时 CDN 拉不到的话 ECharts 方案
// 会直接白屏。
const indexHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ntop2ban</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif;
  background:#f7f8fa;color:#1f2933}
header{display:flex;align-items:center;gap:16px;padding:12px 20px;background:#1f2933;color:#fff}
header h1{margin:0;font-size:16px;font-weight:600;letter-spacing:-.01em}
header .src{font-size:12px;color:#9aa5b1;margin-left:auto}
header a{color:#cbd2d9;font-size:13px;text-decoration:none;margin-left:14px}
header a:hover{color:#fff}
nav{display:flex;gap:2px;padding:0 20px;background:#fff;border-bottom:1px solid #e4e7eb}
nav button{padding:11px 16px;border:0;background:none;font-size:14px;color:#52606d;cursor:pointer;
  border-bottom:2px solid transparent}
nav button.on{color:#1f2933;font-weight:600;border-bottom-color:#1f2933}
main{padding:20px;max-width:1200px}
section{display:none}
section.on{display:block}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.card{flex:1;min-width:180px;background:#fff;border:1px solid #e4e7eb;border-radius:8px;padding:14px 16px}
.card .k{font-size:12px;color:#7b8794;margin-bottom:4px}
.card .v{font-size:21px;font-weight:600;letter-spacing:-.02em}
.card .n{font-size:12px;color:#9aa5b1;margin-top:2px}
.panel{background:#fff;border:1px solid #e4e7eb;border-radius:8px;padding:16px;margin-bottom:18px}
.panel h2{margin:0 0 12px;font-size:14px;font-weight:600}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
select,input,button.act{padding:6px 10px;border:1px solid #cbd2d9;border-radius:5px;font-size:13px;background:#fff}
button.act{background:#1f2933;color:#fff;border-color:#1f2933;cursor:pointer}
button.act:hover{background:#323f4b}
button.ghost{background:#fff;color:#52606d;cursor:pointer}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 10px;color:#7b8794;font-weight:500;border-bottom:1px solid #e4e7eb;font-size:12px}
td{padding:8px 10px;border-bottom:1px solid #f0f2f4}
tr:hover td{background:#fafbfc}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.num{text-align:right;font-variant-numeric:tabular-nums}
.tag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px}
.tag.active{background:#e3f9e5;color:#0b6b2f}
.tag.pending{background:#fff8e1;color:#8a5f00}
.tag.rejected{background:#fdf2f2;color:#a61b1b}
.tag.superseded{background:#f0f2f4;color:#7b8794}
pre{margin:8px 0 0;padding:11px 13px;background:#f7f8fa;border:1px solid #e4e7eb;border-radius:6px;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap}
.hint{color:#7b8794;font-size:12px;margin:6px 0 0}
.err{padding:9px 11px;border-radius:6px;background:#fdf2f2;color:#a61b1b;font-size:13px;margin-bottom:12px;display:none}
.empty{padding:24px;text-align:center;color:#9aa5b1;font-size:13px}
svg{display:block;width:100%;height:auto}
.steps{display:flex;flex-direction:column;gap:8px;margin-bottom:12px}
.step{display:flex;gap:8px;align-items:center}
.step select,.step input{flex:0 0 auto}
.burst{fill:#d64545}
</style>
</head>
<body>
<header>
  <h1>ntop2ban</h1>
  <span class="src" id="src"></span>
  <a href="#" id="who"></a>
  <a href="/logout">退出</a>
</header>
<nav>
  <button class="on" data-t="flows">流量</button>
  <button data-t="probe">链路探测</button>
  <button data-t="knock">敲门</button>
  <button data-t="audit">审计</button>
</nav>
<main>
  <div class="err" id="err"></div>

  <section class="on" id="s-flows">
    <div class="cards" id="ov"></div>
    <div class="panel">
      <h2>流量排行</h2>
      <div class="row">
        <select id="f-min">
          <option value="5">最近 5 分钟</option>
          <option value="15" selected>最近 15 分钟</option>
          <option value="60">最近 1 小时</option>
          <option value="1440">最近 24 小时</option>
        </select>
        <select id="f-order">
          <option value="bytes">按字节</option>
          <option value="packets">按包数</option>
        </select>
        <button class="act" id="f-go">刷新</button>
        <span class="hint" id="f-note"></span>
      </div>
      <div id="f-table"></div>
    </div>
  </section>

  <section id="s-probe">
    <div class="panel">
      <h2>延迟与丢包</h2>
      <div class="row">
        <select id="p-target"></select>
        <select id="p-hours">
          <option value="1">最近 1 小时</option>
          <option value="6" selected>最近 6 小时</option>
          <option value="24">最近 24 小时</option>
          <option value="168">最近 7 天</option>
        </select>
        <button class="act" id="p-go">刷新</button>
      </div>
      <div id="p-chart"></div>
      <p class="hint">带状区域是 RTT 分布(min–p90),深线是中位数;红点是丢包突发(robust z ≥ 3.5)。
        存分布而不是均值——一半 5ms 一半 500ms 与全部 250ms 的均值相同,但那是两种体感截然不同的链路。</p>
    </div>
  </section>

  <section id="s-knock">
    <div class="panel" id="k-active"></div>
    <div class="panel" id="k-new" style="display:none">
      <h2>提交新序列</h2>
      <div class="steps" id="k-steps"></div>
      <div class="row">
        <button class="ghost" id="k-add-tcp">+ TCP 步</button>
        <button class="ghost" id="k-add-icmp">+ ICMP 步</button>
      </div>
      <div class="row">
        <label>放行端口 <input id="k-open" type="number" value="22" style="width:80px"></label>
        <label>序列时限(秒) <input id="k-win" type="number" value="60" style="width:70px"></label>
        <label>放行时长(秒) <input id="k-for" type="number" value="60" style="width:70px"></label>
      </div>
      <div class="row">
        <input id="k-note" placeholder="变更说明" style="flex:1">
        <button class="act" id="k-submit">提交</button>
      </div>
      <p class="hint">不支持 UDP:很多客户端出口环境发不出 UDP,而一个静默不到达的敲门步是最难排查的故障。
        相邻两步不能相同(网络重传会让状态机分不清是下一步还是上一步的重发);ICMP 长度上限 1400,
        再大会在 1500 MTU 链路上分片,分片后长度改变必然敲不开。</p>
    </div>
    <div class="panel">
      <h2>序列版本</h2>
      <div id="k-list"></div>
    </div>
    <div class="panel">
      <h2>成功授权记录</h2>
      <div id="k-grants"></div>
      <p class="hint">只记成功。失败的敲门是互联网噪声,记下来只会淹没这里真正需要看的东西。</p>
    </div>
  </section>

  <section id="s-audit">
    <div class="panel">
      <h2>审计日志</h2>
      <div id="a-list"></div>
    </div>
  </section>
</main>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let ROLE = 'viewer';

function showErr(m) { const e = $('#err'); e.textContent = m; e.style.display = m ? 'block' : 'none'; }

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { location.href = '/login'; return null; }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

function bytes(n) {
  const u = ['B','KB','MB','GB','TB'];
  let i = 0, v = Number(n) || 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(i ? 1 : 0) + ' ' + u[i];
}
function ts(sec) {
  if (!sec) return '—';
  const d = new Date(sec * 1000);
  const p = n => String(n).padStart(2, '0');
  return p(d.getMonth()+1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('on', x === b));
  document.querySelectorAll('section').forEach(s => s.classList.toggle('on', s.id === 's-' + b.dataset.t));
  load(b.dataset.t);
});

async function loadOverview() {
  const d = await api('/api/v1/overview');
  if (!d) return;
  ROLE = d.role;
  $('#who').textContent = d.user + ' (' + d.role + ')';
  $('#src').textContent = '数据源:' + (d.data_source || '未知');
  $('#k-new').style.display = (ROLE === 'admin') ? 'block' : 'none';

  const st = d.storage || {};
  $('#ov').innerHTML =
    card('存储后端', st.backend || '—', 'SQLite 单文件,拷走即备份') +
    card('采样记录', (st.total_rows || 0).toLocaleString(), st.oldest ? ('最早 ' + ts(st.oldest)) : '暂无数据') +
    card('敲门序列', d.knock ? (d.knock.steps.length + ' 步') : '未配置',
         d.knock ? ('放行端口 ' + d.knock.open_port + ',' + d.knock.window + ' 内完成') : '在敲门页提交并审批');
}
function card(k, v, n) {
  return '<div class="card"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) +
         '</div><div class="n">' + esc(n) + '</div></div>';
}

async function loadFlows() {
  const d = await api('/api/v1/flows/top?minutes=' + $('#f-min').value + '&order=' + $('#f-order').value + '&limit=50');
  if (!d) return;
  if (!d.rows.length) { $('#f-table').innerHTML = '<div class="empty">这段时间没有采样数据</div>'; $('#f-note').textContent = ''; return; }
  const n = d.rows[0].sampling_n || 1;
  $('#f-note').textContent = n > 1 ? ('采样率 1/' + n + ',估算流量 = 实测 × ' + n) : '全量采集';
  let h = '<table><tr><th>源</th><th>目的</th><th>协议</th>' +
          '<th class="num">实测包</th><th class="num">实测字节</th><th class="num">估算字节</th><th>最后见到</th></tr>';
  for (const r of d.rows) {
    h += '<tr><td class="mono">' + esc(r.src_ip) + ':' + r.src_port + '</td>' +
         '<td class="mono">' + esc(r.dst_ip) + ':' + r.dst_port + '</td>' +
         '<td>' + esc(r.proto) + '</td>' +
         '<td class="num">' + r.pkts.toLocaleString() + '</td>' +
         '<td class="num">' + bytes(r.bytes) + '</td>' +
         '<td class="num">' + bytes(r.est_bytes) + '</td>' +
         '<td class="mono">' + ts(r.last_seen) + '</td></tr>';
  }
  $('#f-table').innerHTML = h + '</table>';
}

async function loadProbeTargets() {
  const d = await api('/api/v1/probe/targets');
  if (!d) return;
  const sel = $('#p-target');
  const prev = sel.value;
  sel.innerHTML = d.targets.map(t => '<option>' + esc(t) + '</option>').join('');
  if (prev && d.targets.includes(prev)) sel.value = prev;
  if (!d.targets.length) {
    // 提示要具体到"去哪个文件改",而不是一句"没有数据"——
    // 空白图表让人以为程序坏了,明确的指引才知道下一步做什么。
    $('#p-chart').innerHTML = '<div class="empty">' +
      esc(d.hint || '还没有探测目标。编辑 /etc/ntop2ban/ping.list 或 tcp.list,每行一个目标,重启生效') +
      '</div>';
    return;
  }
  await loadProbe();
}

async function loadProbe() {
  const t = $('#p-target').value;
  if (!t) return;
  const d = await api('/api/v1/probe/rounds?target=' + encodeURIComponent(t) + '&hours=' + $('#p-hours').value);
  if (!d) return;
  $('#p-chart').innerHTML = d.rounds.length ? chart(d.rounds) : '<div class="empty">这段时间没有探测数据</div>';
}

// 手绘 SVG:分位带 + 中位数折线 + 突发标记。不引入图表库的理由见
// 本文件顶部注释。
function chart(rounds) {
  const W = 1100, H = 260, PL = 52, PR = 12, PT = 12, PB = 26;
  const iw = W - PL - PR, ih = H - PT - PB;
  const t0 = rounds[0].t, t1 = rounds[rounds.length - 1].t || (t0 + 1);
  let vmax = 0;
  for (const r of rounds) if (r.p90 > vmax) vmax = r.p90;
  if (vmax <= 0) vmax = 1;
  vmax *= 1.15;

  const X = t => PL + (t1 === t0 ? iw / 2 : (t - t0) / (t1 - t0) * iw);
  const Y = v => PT + ih - Math.min(v, vmax) / vmax * ih;

  let band = '', line = '', dots = '';
  const top = [], bot = [];
  for (const r of rounds) { top.push(X(r.t) + ',' + Y(r.p90)); bot.push(X(r.t) + ',' + Y(r.min)); }
  band = '<polygon points="' + top.join(' ') + ' ' + bot.reverse().join(' ') + '" fill="#2f6feb22"/>';
  line = '<polyline points="' + rounds.map(r => X(r.t) + ',' + Y(r.p50)).join(' ') +
         '" fill="none" stroke="#2f6feb" stroke-width="1.6"/>';
  for (const r of rounds) if (r.burst) dots += '<circle class="burst" cx="' + X(r.t) + '" cy="' + Y(r.p50) + '" r="3.2"/>';

  let axis = '';
  for (let i = 0; i <= 4; i++) {
    const v = vmax * i / 4, y = Y(v);
    axis += '<line x1="' + PL + '" y1="' + y + '" x2="' + (W - PR) + '" y2="' + y + '" stroke="#eef0f2"/>' +
            '<text x="' + (PL - 8) + '" y="' + (y + 4) + '" text-anchor="end" font-size="11" fill="#9aa5b1">' +
            v.toFixed(v < 10 ? 1 : 0) + 'ms</text>';
  }
  for (let i = 0; i <= 4; i++) {
    const t = t0 + (t1 - t0) * i / 4, x = X(t);
    axis += '<text x="' + x + '" y="' + (H - 8) + '" text-anchor="middle" font-size="11" fill="#9aa5b1">' + ts(t) + '</text>';
  }

  const lossPts = rounds.filter(r => r.loss > 0);
  const lossNote = lossPts.length
    ? ('<p class="hint">区间内 ' + lossPts.length + '/' + rounds.length + ' 轮有丢包,最高 ' +
       Math.max.apply(null, lossPts.map(r => r.loss)).toFixed(1) + '%</p>')
    : '<p class="hint">区间内零丢包</p>';

  return '<svg viewBox="0 0 ' + W + ' ' + H + '">' + axis + band + line + dots + '</svg>' + lossNote;
}

async function loadKnock() {
  const ov = await api('/api/v1/overview');
  if (!ov) return;
  const k = ov.knock;
  $('#k-active').innerHTML = k
    ? '<h2>当前生效的序列 #' + k.id + '</h2><pre>' + esc(k.client_script) + '</pre>' +
      '<p class="hint">这些命令用系统自带的 nc 与 ping 即可完成,不需要任何客户端工具。' +
      '暗号固定不轮换——轮换需要先查当前值,而查询页往往也在敲门保护之后,鸡生蛋。</p>'
    : '<h2>当前没有生效的序列</h2><p class="hint">' +
      (ROLE === 'admin' ? '在下面提交一版并审批。' : '请联系 admin 配置。') + '</p>';

  const d = await api('/api/v1/knock/sequences');
  if (!d) return;
  if (!d.sequences.length) { $('#k-list').innerHTML = '<div class="empty">还没有提交过序列</div>'; }
  else {
    let h = '<table><tr><th>#</th><th>序列</th><th>放行</th><th>状态</th><th>提交人</th><th>审批人</th><th>时间</th><th></th></tr>';
    for (const s of d.sequences) {
      const steps = s.steps.map(x => x.kind === 'tcp' ? ('tcp/' + x.port) : ('icmp/len=' + x.payload_len)).join(' → ');
      let act = '';
      if (ROLE === 'admin' && s.state === 'pending') {
        act = '<button class="act" onclick="approve(' + s.id + ')">批准</button> ' +
              '<button class="ghost" onclick="reject(' + s.id + ')">驳回</button>';
      }
      h += '<tr><td>' + s.id + '</td><td class="mono">' + esc(steps) + '</td>' +
           '<td>' + s.open_port + ' / ' + esc(s.open_for) + '</td>' +
           '<td><span class="tag ' + esc(s.state) + '">' + esc(s.state) + '</span></td>' +
           '<td>' + esc(s.requested_by) + '</td><td>' + esc(s.approved_by || '—') + '</td>' +
           '<td class="mono">' + ts(s.created_at) + '</td><td>' + act + '</td></tr>';
    }
    $('#k-list').innerHTML = h + '</table>';
  }

  const g = await api('/api/v1/knock/grants');
  if (!g) return;
  if (!g.grants.length) { $('#k-grants').innerHTML = '<div class="empty">还没有成功的敲门</div>'; return; }
  let gh = '<table><tr><th>来源 IP</th><th>放行端口</th><th>授权时刻</th><th>到期</th></tr>';
  for (const x of g.grants) {
    gh += '<tr><td class="mono">' + esc(x.src_ip) + '</td><td>' + x.open_port + '</td>' +
          '<td class="mono">' + ts(x.granted_at) + '</td><td class="mono">' + ts(x.expires_at) + '</td></tr>';
  }
  $('#k-grants').innerHTML = gh + '</table>';
}

async function approve(id) {
  try { await api('/api/v1/knock/approve', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id})}); showErr(''); loadKnock(); }
  catch (e) { showErr(e.message); }
}
async function reject(id) {
  const note = prompt('驳回原因?') || '';
  try { await api('/api/v1/knock/reject', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id, note})}); showErr(''); loadKnock(); }
  catch (e) { showErr(e.message); }
}

function addStep(kind) {
  const d = document.createElement('div');
  d.className = 'step';
  d.innerHTML = kind === 'tcp'
    ? '<select data-k="tcp"><option value="tcp">TCP 端口</option></select><input type="number" value="9001" style="width:100px">'
    : '<select data-k="icmp"><option value="icmp">ICMP 长度</option></select><input type="number" value="56" style="width:100px">';
  const rm = document.createElement('button');
  rm.className = 'ghost'; rm.textContent = '删除';
  rm.onclick = () => d.remove();
  d.appendChild(rm);
  $('#k-steps').appendChild(d);
}
$('#k-add-tcp').onclick = () => addStep('tcp');
$('#k-add-icmp').onclick = () => addStep('icmp');

$('#k-submit').onclick = async () => {
  const steps = [];
  for (const el of document.querySelectorAll('#k-steps .step')) {
    const kind = el.querySelector('select').dataset.k;
    const v = parseInt(el.querySelector('input').value, 10);
    steps.push(kind === 'tcp' ? {kind:'tcp', port:v} : {kind:'icmp', payload_len:v});
  }
  try {
    await api('/api/v1/knock/submit', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({steps, open_port: +$('#k-open').value,
        window_sec: +$('#k-win').value, open_for_sec: +$('#k-for').value, note: $('#k-note').value})});
    showErr(''); $('#k-steps').innerHTML = ''; $('#k-note').value = ''; loadKnock();
  } catch (e) { showErr(e.message); }
};

async function loadAudit() {
  const d = await api('/api/v1/audit');
  if (!d) return;
  if (!d.entries.length) { $('#a-list').innerHTML = '<div class="empty">暂无记录</div>'; return; }
  let h = '<table><tr><th>时间</th><th>操作者</th><th>动作</th><th>对象</th><th>说明</th></tr>';
  for (const e of d.entries) {
    h += '<tr><td class="mono">' + ts(e.at) + '</td><td>' + esc(e.actor) + '</td>' +
         '<td class="mono">' + esc(e.action) + '</td><td class="mono">' + esc(e.target) + '</td>' +
         '<td>' + esc(e.detail) + '</td></tr>';
  }
  $('#a-list').innerHTML = h + '</table>';
}

$('#f-go').onclick = () => loadFlows().catch(e => showErr(e.message));
$('#p-go').onclick = () => loadProbe().catch(e => showErr(e.message));

function load(tab) {
  showErr('');
  const f = {flows: loadFlows, probe: loadProbeTargets, knock: loadKnock, audit: loadAudit}[tab];
  if (f) f().catch(e => showErr(e.message));
}

(async () => {
  try { await loadOverview(); await loadFlows(); addStep('tcp'); addStep('icmp'); }
  catch (e) { showErr(e.message); }
})();
setInterval(() => { const on = document.querySelector('nav button.on').dataset.t;
  if (on === 'flows') { loadOverview().catch(()=>{}); loadFlows().catch(()=>{}); } }, 15000);
</script>
</body>
</html>
`
