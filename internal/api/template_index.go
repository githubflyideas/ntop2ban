package api

// Dashboard 与 Explorer。深色主题、手写 SVG 图表,不引外部框架或 CDN。
//
// 为什么不用 ECharts:1MB 的 JS 嵌进单一二进制会让体积翻倍,而这里
// 需要的图形(堆叠面积、横向条形、甜甜圈)用 SVG 各几十行就能画;
// 更重要的是内网部署时 CDN 拉不到会直接白屏。
//
// 所有数据都走 POST /api/v1/query 提交 Query AST。每个卡片、每次下钻
// 都是一次 AST 请求 —— 同一个引擎服务所有视图。
const indexHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ntop2ban</title>
<style>
:root{color-scheme:dark;
 --bg:#0f1520; --panel:#161d29; --line:#232c3b; --line2:#2b3546;
 --fg:#e6edf3; --dim:#8b95a3; --dim2:#5f6977;
 --blue:#3d7eff; --cyan:#00c2d7; --green:#2fbf71; --amber:#e8a33d;
 --red:#e5534b; --purple:#a371f7; --pink:#db61a2}
*{box-sizing:border-box}
body{margin:0;font:13.5px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
 background:var(--bg);color:var(--fg)}
a{color:var(--blue);text-decoration:none}

header{display:flex;align-items:center;gap:14px;padding:0 18px;height:48px;
 background:var(--panel);border-bottom:1px solid var(--line)}
header .logo{font-size:15px;font-weight:600;letter-spacing:-.02em}
header .logo span{color:var(--blue)}
header .meta{margin-left:auto;display:flex;gap:16px;align-items:center;font-size:12px;color:var(--dim)}
header .meta b{color:var(--fg);font-weight:500}
header .out{color:var(--dim);font-size:12px}

nav{display:flex;gap:4px;padding:0 18px;background:var(--panel);border-bottom:1px solid var(--line)}
nav button{padding:10px 14px;border:0;background:none;font-size:13px;color:var(--dim);
 cursor:pointer;border-bottom:2px solid transparent}
nav button:hover{color:var(--fg)}
nav button.on{color:var(--fg);border-bottom-color:var(--blue)}

main{padding:16px 18px 40px;max-width:1600px}
section{display:none}
section.on{display:block}

.bar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
select,input[type=text],input[type=number]{padding:6px 9px;background:var(--panel);
 border:1px solid var(--line2);border-radius:5px;font-size:12.5px;color:var(--fg)}
select:focus,input:focus{outline:none;border-color:var(--blue)}
button.act{padding:6px 13px;border:0;border-radius:5px;background:var(--blue);
 color:#fff;font-size:12.5px;cursor:pointer}
button.act:hover{background:#5590ff}
button.gh{padding:6px 11px;background:var(--panel);border:1px solid var(--line2);
 border-radius:5px;color:var(--dim);font-size:12.5px;cursor:pointer}
button.gh:hover{color:var(--fg);border-color:var(--dim2)}

.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:13px 15px}
.kpi .k{font-size:11.5px;color:var(--dim);margin-bottom:5px;letter-spacing:.02em}
.kpi .v{font-size:22px;font-weight:600;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.kpi .n{font-size:11px;color:var(--dim2);margin-top:3px}

.grid{display:grid;gap:12px}
.g2{grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}
.g3{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:14px}
.panel h2{margin:0 0 2px;font-size:13px;font-weight:600}
.panel .hint{margin:0 0 11px;font-size:11.5px;color:var(--dim2)}
.panel.wide{grid-column:1/-1}

table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;padding:6px 8px;color:var(--dim);font-weight:500;font-size:11.5px;
 border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:6px 8px;border-bottom:1px solid rgba(35,44,59,.55)}
tr:last-child td{border-bottom:0}
tbody tr:hover td{background:rgba(61,126,255,.06)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px}
.num{text-align:right;font-variant-numeric:tabular-nums}
.drill{color:var(--blue);cursor:pointer}
.drill:hover{text-decoration:underline}

/* 横向条形:用背景渐变画条,不需要 SVG */
.barcell{position:relative;padding:5px 8px}
.barcell .fill{position:absolute;left:0;top:0;bottom:0;background:rgba(61,126,255,.18);border-radius:3px}
.barcell .txt{position:relative}

.empty{padding:26px;text-align:center;color:var(--dim2);font-size:12.5px}
.err{padding:10px 12px;border-radius:6px;background:#2d1618;color:#ff9c9c;
 font-size:12.5px;margin-bottom:12px;display:none}
svg{display:block;width:100%;height:auto}
.legend{display:flex;gap:12px;flex-wrap:wrap;margin-top:9px;font-size:11.5px;color:var(--dim)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}

.cond{display:flex;gap:7px;align-items:center;margin-bottom:7px}
.cond select,.cond input{font-size:12px}
pre{margin:9px 0 0;padding:11px;background:#0f1520;border:1px solid var(--line);
 border-radius:6px;font-family:ui-monospace,Menlo,monospace;font-size:11.5px;
 overflow-x:auto;white-space:pre-wrap;color:var(--dim)}
.ok{color:var(--green)}
.warn{color:var(--amber)}
.src{border:1px solid var(--line);border-radius:7px;padding:11px 13px;margin-bottom:8px}
.src .top{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.src .nm{font-weight:600;font-size:12.5px}
.src .lic{font-size:11px;color:var(--dim2)}
.src .fl{font-size:11.5px;color:var(--cyan);margin-top:4px}
.src .nt{font-size:11.5px;color:var(--dim);margin-top:3px}
.src button{margin-left:auto}
.tag{display:inline-block;padding:1px 7px;border-radius:9px;font-size:11px;
 background:rgba(61,126,255,.14);color:#8ab4ff}
.up{border:1px dashed var(--line2);border-radius:8px;padding:16px;text-align:center;color:var(--dim)}
</style>
</head>
<body>
<header>
  <div class="logo">ntop<span>2</span>ban</div>
  <div class="meta" id="hdr"></div>
  <a class="out" href="/logout">退出</a>
</header>
<nav>
  <button class="on" data-t="dash">Dashboard</button>
  <button data-t="hosts">Hosts</button>
  <button data-t="conv">Conversations</button>
  <button data-t="geo">ASN / Country</button>
  <button data-t="explore">Explorer</button>
  <button data-t="settings">设置</button>
</nav>
<main>
  <div class="err" id="err"></div>

  <div class="bar">
    <select id="range">
      <option value="15m">最近 15 分钟</option>
      <option value="1h" selected>最近 1 小时</option>
      <option value="6h">最近 6 小时</option>
      <option value="24h">最近 24 小时</option>
      <option value="7d">最近 7 天</option>
      <option value="30d">最近 30 天</option>
    </select>
    <select id="metric">
      <option value="bytes">按字节</option>
      <option value="packets">按包数</option>
      <option value="flows">按流数</option>
    </select>
    <button class="act" id="refresh">刷新</button>
    <span class="hint" id="scope" style="color:var(--dim2);font-size:11.5px"></span>
  </div>

  <section class="on" id="s-dash">
    <div class="kpis" id="kpis"></div>
    <div class="grid g2">
      <div class="panel wide">
        <h2>流量趋势</h2>
        <p class="hint">按分钟聚合;估算值(已按采样率还原)</p>
        <div id="ts"></div>
      </div>
      <div class="panel"><h2>Top Talkers(源)</h2><p class="hint">谁发出最多</p><div id="topsrc"></div></div>
      <div class="panel"><h2>Top Destinations(目的)</h2><p class="hint">流量去了哪</p><div id="topdst"></div></div>
      <div class="panel"><h2>应用(按端口推断)</h2><p class="hint">端口推断,不是 DPI 确认</p><div id="topapp"></div></div>
      <div class="panel"><h2>协议</h2><p class="hint"></p><div id="topproto"></div></div>
      <div class="panel"><h2>Top 目的端口</h2><p class="hint"></p><div id="topport"></div></div>
      <div class="panel"><h2>Top ASN</h2><p class="hint">需要 ip2asn 库</p><div id="topasn"></div></div>
    </div>
  </section>

  <section id="s-hosts">
    <div class="grid g2">
      <div class="panel"><h2>Top 源主机</h2><p class="hint">点 IP 下钻</p><div id="h-src"></div></div>
      <div class="panel"><h2>Top 目的主机</h2><p class="hint">点 IP 下钻</p><div id="h-dst"></div></div>
    </div>
    <div class="panel wide" id="h-detail" style="margin-top:12px;display:none"></div>
  </section>

  <section id="s-conv">
    <div class="panel"><h2>Top Conversations</h2>
      <p class="hint">源 ↔ 目的 的流量对</p><div id="c-list"></div></div>
  </section>

  <section id="s-geo">
    <div class="grid g2">
      <div class="panel"><h2>Top 源国家</h2><div id="g-srcc"></div></div>
      <div class="panel"><h2>Top 目的国家</h2><div id="g-dstc"></div></div>
      <div class="panel"><h2>Top 源 ASN</h2><div id="g-srca"></div></div>
      <div class="panel"><h2>Top 组织</h2><div id="g-org"></div></div>
      <div class="panel" id="g-city-wrap"><h2>Top 城市</h2>
        <p class="hint" id="g-city-hint"></p><div id="g-city"></div></div>
    </div>
  </section>

  <section id="s-explore">
    <div class="panel">
      <h2>Query Builder</h2>
      <p class="hint">界面提交 Query AST,不拼 SQL —— 字段与运算符都有白名单</p>
      <div id="conds"></div>
      <div class="bar">
        <button class="gh" id="addcond">+ 条件</button>
        <select id="e-logic"><option value="AND">全部满足 (AND)</option><option value="OR">任一满足 (OR)</option></select>
      </div>
      <div class="bar">
        <label style="color:var(--dim);font-size:12px">分组</label>
        <select id="e-group"></select>
        <label style="color:var(--dim);font-size:12px">指标</label>
        <select id="e-metric"></select>
        <label style="color:var(--dim);font-size:12px">条数</label>
        <input type="number" id="e-limit" value="100" style="width:78px">
        <button class="act" id="e-run">查询</button>
        <button class="gh" id="e-explain">查看 SQL</button>
      </div>
      <div id="e-sql"></div>
      <div id="e-out" style="margin-top:12px"></div>
    </div>
  </section>

  <section id="s-settings">
    <div class="grid g2">
      <div class="panel wide">
        <h2>富化库</h2>
        <p class="hint">当前状态</p>
        <div id="set-enrich"></div>

        <h2 style="margin-top:16px">在线同步</h2>
        <p class="hint">下面这些源都免费、无需注册。点一下即可下载并立即生效,
          历史数据保持当时的快照不会被回填。</p>
        <div id="sync-status"></div>
        <div id="sync-list"></div>

        <h2 style="margin-top:16px">上传 GeoLite2-City.mmdb</h2>
        <p class="hint">MaxMind 的库精度最高,但需要注册账号拿 license key,
          所以不能内置自动同步 —— 手动下载后从这里上传</p>
        <div class="up">
          <input type="file" id="mmdbfile" accept=".mmdb">
          <button class="act" id="mmdbup" style="margin-left:8px">上传并生效</button>
        </div>
      </div>
      <div class="panel">
        <h2>输入源与存储</h2>
        <div id="set-sys"></div>
      </div>
    </div>
  </section>
</main>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const PAL = ['#3d7eff','#00c2d7','#2fbf71','#e8a33d','#a371f7','#db61a2','#e5534b','#5f6977'];
let FIELDS = null, DRILL = null;

function showErr(m){const e=$('#err');e.textContent=m||'';e.style.display=m?'block':'none';}

async function api(path, body){
  const r = await fetch(path, body?{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(body)}:undefined);
  if(r.status===401){location.href='/login';return null;}
  const d = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(d.error||('HTTP '+r.status));
  return d;
}

// 时间范围:前端算出绝对区间再提交 —— AST 里必须是绝对时间,
// 否则同一个 AST 在不同时刻含义不同,没法保存/复现查询。
function timeRange(){
  const v = $('#range').value;
  const n = parseInt(v), unit = v.slice(-1);
  const ms = unit==='m'?n*6e4 : unit==='h'?n*36e5 : n*864e5;
  const to = new Date(), from = new Date(to.getTime()-ms);
  return {from:from.toISOString(), to:to.toISOString()};
}
function spanMs(){
  const v=$('#range').value, n=parseInt(v), u=v.slice(-1);
  return u==='m'?n*6e4:u==='h'?n*36e5:n*864e5;
}
function metric(){ return $('#metric').value; }

function fmtBytes(n){
  n = Number(n)||0;
  const u=['B','KB','MB','GB','TB','PB']; let i=0;
  while(n>=1024&&i<u.length-1){n/=1024;i++;}
  return n.toFixed(i?(n<10?2:1):0)+' '+u[i];
}
function fmtNum(n){
  n = Number(n)||0;
  if(n>=1e9) return (n/1e9).toFixed(2)+'G';
  if(n>=1e6) return (n/1e6).toFixed(2)+'M';
  if(n>=1e3) return (n/1e3).toFixed(1)+'K';
  return String(n);
}
function fmtMetric(v){ return metric()==='bytes'?fmtBytes(v):fmtNum(v); }
function ts(sec){
  if(!sec) return '—';
  const d=new Date(sec*1000), p=n=>String(n).padStart(2,'0');
  return p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes());
}

// 每个视图都是一次 Query AST。这个函数是所有图表的唯一数据来源。
function ast(o){
  return Object.assign({time_range:timeRange(), limit:10, metrics:[metric()]}, o);
}

async function topTable(el, groupBy, opts){
  opts = opts||{};
  const q = ast({group_by:[groupBy], limit:opts.limit||10,
                 metrics:[metric()], filters:opts.filters});
  let d;
  try { d = await api('/api/v1/query', q); } catch(e){ el.innerHTML='<div class="empty">'+esc(e.message)+'</div>'; return; }
  if(!d) return;
  if(!d.rows.length){ el.innerHTML='<div class="empty">这段时间没有数据</div>'; return; }

  const max = Math.max.apply(null, d.rows.map(r=>Number(r[1])||0)) || 1;
  let h='<table><tbody>';
  for(const r of d.rows){
    const label = r[0], val = Number(r[1])||0;
    const pct = (val/max*100).toFixed(1);
    const disp = opts.fmt ? opts.fmt(label) : esc(label);
    const clickable = opts.drill ? ' class="drill" data-drill="'+esc(opts.drill)+'" data-val="'+esc(label)+'"' : '';
    h += '<tr><td class="barcell"><span class="fill" style="width:'+pct+'%"></span>'
       + '<span class="txt mono"'+clickable+'>'+disp+'</span></td>'
       + '<td class="num">'+fmtMetric(val)+'</td></tr>';
  }
  el.innerHTML = h+'</tbody></table>';
  el.querySelectorAll('[data-drill]').forEach(n=>n.onclick=()=>drillTo(n.dataset.drill, n.dataset.val));
}

// 堆叠面积图:时间序列。手绘 SVG,理由见本文件顶部注释。
async function timeseries(el){
  // 跨度大时按小时聚合,避免几万个点画不动也看不清
  const interval = spanMs() > 6*36e5 ? 'hour' : 'minute';
  const q = ast({interval:interval, limit:5000, metrics:[metric()],
                 sort:{field:'ts',desc:false}});
  let d;
  try { d = await api('/api/v1/query', q); } catch(e){ el.innerHTML='<div class="empty">'+esc(e.message)+'</div>'; return; }
  if(!d || !d.rows.length){ el.innerHTML='<div class="empty">这段时间没有数据</div>'; return; }

  const pts = d.rows.map(r=>({t:Number(r[0]), v:Number(r[1])||0})).sort((a,b)=>a.t-b.t);
  el.innerHTML = areaChart(pts, interval);
}

function areaChart(pts, interval){
  const W=1160,H=210,PL=58,PR=10,PT=10,PB=24;
  const iw=W-PL-PR, ih=H-PT-PB;
  const t0=pts[0].t, t1=pts[pts.length-1].t||t0+1;
  let vmax=0; for(const p of pts) if(p.v>vmax) vmax=p.v;
  if(vmax<=0) vmax=1;
  vmax*=1.12;
  const X=t=>PL+(t1===t0?iw/2:(t-t0)/(t1-t0)*iw);
  const Y=v=>PT+ih-v/vmax*ih;

  let grid='';
  for(let i=0;i<=4;i++){
    const v=vmax*i/4, y=Y(v);
    grid+='<line x1="'+PL+'" y1="'+y+'" x2="'+(W-PR)+'" y2="'+y+'" stroke="#232c3b"/>'
        + '<text x="'+(PL-7)+'" y="'+(y+4)+'" text-anchor="end" font-size="10.5" fill="#5f6977">'
        + (metric()==='bytes'?fmtBytes(v):fmtNum(v))+'</text>';
  }
  for(let i=0;i<=5;i++){
    const t=t0+(t1-t0)*i/5, x=X(t);
    grid+='<text x="'+x+'" y="'+(H-6)+'" text-anchor="middle" font-size="10.5" fill="#5f6977">'+ts(t)+'</text>';
  }

  const line=pts.map(p=>X(p.t)+','+Y(p.v)).join(' ');
  const area=PL+','+(PT+ih)+' '+line+' '+(X(t1))+','+(PT+ih);
  return '<svg viewBox="0 0 '+W+' '+H+'">'
    + '<defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">'
    + '<stop offset="0" stop-color="#3d7eff" stop-opacity=".42"/>'
    + '<stop offset="1" stop-color="#3d7eff" stop-opacity=".02"/></linearGradient></defs>'
    + grid
    + '<polygon points="'+area+'" fill="url(#ag)"/>'
    + '<polyline points="'+line+'" fill="none" stroke="#3d7eff" stroke-width="1.7"/>'
    + '</svg>'
    + '<div class="legend"><span><i style="background:#3d7eff"></i>'
    + (metric()==='bytes'?'字节':metric()==='packets'?'包数':'流数')
    + '(' + (interval==='hour'?'每小时':'每分钟') + ')</span></div>';
}

// 甜甜圈:协议 / 应用构成
async function donut(el, groupBy){
  const q = ast({group_by:[groupBy], limit:8, metrics:[metric()]});
  let d;
  try { d = await api('/api/v1/query', q); } catch(e){ el.innerHTML='<div class="empty">'+esc(e.message)+'</div>'; return; }
  if(!d || !d.rows.length){ el.innerHTML='<div class="empty">这段时间没有数据</div>'; return; }

  const rows=d.rows.map(r=>({k:String(r[0]), v:Number(r[1])||0}));
  const total=rows.reduce((a,b)=>a+b.v,0)||1;
  const R=64, C=80, SW=20;
  let acc=0, arcs='', legend='';
  rows.forEach((r,i)=>{
    const frac=r.v/total;
    const len=2*Math.PI*R*frac, gap=2*Math.PI*R-len;
    arcs+='<circle cx="'+C+'" cy="'+C+'" r="'+R+'" fill="none" stroke="'+PAL[i%PAL.length]+'"'
        + ' stroke-width="'+SW+'" stroke-dasharray="'+len+' '+gap+'"'
        + ' stroke-dashoffset="'+(-acc)+'" transform="rotate(-90 '+C+' '+C+')"/>';
    acc+=len;
    legend+='<span><i style="background:'+PAL[i%PAL.length]+'"></i>'+esc(r.k)
          + ' <span style="color:var(--dim2)">'+(frac*100).toFixed(1)+'%</span></span>';
  });
  el.innerHTML='<div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap">'
    + '<svg viewBox="0 0 160 160" style="width:150px;flex:0 0 auto">'+arcs
    + '<text x="80" y="76" text-anchor="middle" font-size="11" fill="#8b95a3">合计</text>'
    + '<text x="80" y="93" text-anchor="middle" font-size="14" font-weight="600" fill="#e6edf3">'
    + fmtMetric(total)+'</text></svg>'
    + '<div class="legend" style="flex-direction:column;gap:6px;margin:0">'+legend+'</div></div>';
}

async function loadOverview(){
  const d = await api('/api/v1/overview');
  if(!d) return;
  const st = d.storage||{}, en = d.enrich||{};
  $('#hdr').innerHTML =
    '<span>输入 <b>'+esc((d.inputs||[]).join(' + ')||'—')+'</b></span>'
    + '<span>flows <b>'+fmtNum(st.rows)+'</b></span>'
    + '<span>磁盘 <b>'+(st.compressed_gb||0).toFixed(2)+' GB</b></span>'
    + '<span>'+esc(d.user)+'</span>';

  $('#set-enrich').innerHTML =
    '<table><tbody>'
    + row('ASN / 国家 / 组织', en.asn_loaded
        ? ('<span class="ok">可用</span> · '+fmtNum(en.asn_entries)+' 条前缀')
        : '<span class="warn">不可用</span> —— 同步任一 ASN 源即可')
    + row('城市 / 省州', en.city_ready
        ? ('<span class="ok">可用</span> · '+(en.mmdb_loaded
             ? ('GeoLite2 '+esc(en.mmdb_build||''))
             : (esc(en.city_source||'')+' · '+fmtNum(en.city_entries)+' 条')))
        : '<span class="warn">不可用</span> —— 同步 DB-IP City 或上传 GeoLite2')
    + '</tbody></table>';

  $('#set-sys').innerHTML =
    '<table><tbody>'
    + row('输入源', esc((d.inputs||[]).join(', ')||'—'))
    + row('flows 行数', fmtNum(st.rows))
    + row('时间范围', esc(st.oldest||'—')+' → '+esc(st.newest||'—'))
    + row('磁盘(压缩)', (st.compressed_gb||0).toFixed(2)+' GB')
    + row('磁盘(未压缩)', (st.uncompressed_gb||0).toFixed(2)+' GB')
    + '</tbody></table>';

  // 没有 mmdb 时城市视图给出原因,而不是显示一张空表 ——
  // 空表让人以为程序坏了。
  const cityHint = $('#g-city-hint');
  if(!en.mmdb_loaded){
    cityHint.textContent = '需要 GeoLite2-City 库。在「设置」里上传后即可用。';
    $('#g-city').innerHTML = '';
  } else {
    cityHint.textContent = '';
  }
  return d;
}
function row(k,v){ return '<tr><td style="color:var(--dim)">'+k+'</td><td>'+v+'</td></tr>'; }

async function loadKPI(){
  const q = ast({limit:1, metrics:['bytes','packets','flows','observed_bytes','uniq_src_ip','uniq_dst_port'],
                 table:'flows'});
  delete q.sort;
  let d;
  try { d = await api('/api/v1/query', q); } catch(e){ $('#kpis').innerHTML=''; showErr(e.message); return; }
  if(!d || !d.rows.length){ $('#kpis').innerHTML='<div class="kpi"><div class="k">暂无数据</div><div class="v">—</div><div class="n">这段时间没有采集到流量</div></div>'; return; }
  const r = d.rows[0];
  const [bytes,pkts,flows,obs,usrc,udport] = r.map(Number);
  // 估算值与实测值并列展示:让人能判断这个数字是量出来的还是算出来的
  const ratio = obs>0 ? (bytes/obs) : 1;
  $('#kpis').innerHTML =
    kpi('总流量(估算)', fmtBytes(bytes), '实测 '+fmtBytes(obs)+(ratio>1.5?' × 采样率':''))
    + kpi('包数', fmtNum(pkts), '')
    + kpi('流数', fmtNum(flows), '')
    + kpi('活跃源 IP', fmtNum(usrc), '去重')
    + kpi('目的端口', fmtNum(udport), '去重');
}
function kpi(k,v,n){ return '<div class="kpi"><div class="k">'+k+'</div><div class="v">'+v+'</div><div class="n">'+n+'</div></div>'; }

async function loadDash(){
  showErr('');
  $('#scope').textContent='';
  await Promise.all([
    loadKPI(),
    timeseries($('#ts')),
    topTable($('#topsrc'),'src_ip',{drill:'src_ip'}),
    topTable($('#topdst'),'dst_ip',{drill:'dst_ip'}),
    donut($('#topapp'),'application'),
    donut($('#topproto'),'protocol'),
    topTable($('#topport'),'dst_port'),
    topTable($('#topasn'),'src_asn',{fmt:v=>v==='0'?'<span style="color:var(--dim2)">未知</span>':'AS'+esc(v)}),
  ]);
}

async function loadHosts(){
  showErr('');
  await Promise.all([
    topTable($('#h-src'),'src_ip',{limit:20,drill:'src_ip'}),
    topTable($('#h-dst'),'dst_ip',{limit:20,drill:'dst_ip'}),
  ]);
}

// 下钻:每次点击都变成一组新的 Query AST(技术设计 §21)。
async function drillTo(field, value){
  DRILL = {field, value};
  document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('on', b.dataset.t==='hosts'));
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('on', s.id==='s-hosts'));

  const box = $('#h-detail');
  box.style.display='block';
  box.innerHTML = '<h2>'+esc(value)+' <span class="tag">'+esc(field)+'</span></h2>'
    + '<p class="hint">该主机的构成。点上面的其他 IP 可切换。</p>'
    + '<div class="grid g3">'
    + '<div><h2 style="font-size:12px;color:var(--dim)">Top 对端</h2><div id="d-peer"></div></div>'
    + '<div><h2 style="font-size:12px;color:var(--dim)">Top 端口</h2><div id="d-port"></div></div>'
    + '<div><h2 style="font-size:12px;color:var(--dim)">应用</h2><div id="d-app"></div></div>'
    + '<div><h2 style="font-size:12px;color:var(--dim)">对端国家</h2><div id="d-country"></div></div>'
    + '<div><h2 style="font-size:12px;color:var(--dim)">对端 ASN</h2><div id="d-asn"></div></div>'
    + '<div><h2 style="font-size:12px;color:var(--dim)">协议</h2><div id="d-proto"></div></div>'
    + '</div>';

  const f = {field:field, operator:'eq', value:value};
  const peer = field==='src_ip' ? 'dst_ip' : 'src_ip';
  const peerCountry = field==='src_ip' ? 'dst_country' : 'src_country';
  const peerASN = field==='src_ip' ? 'dst_asn' : 'src_asn';

  await Promise.all([
    topTable($('#d-peer'), peer, {filters:f, drill:peer}),
    topTable($('#d-port'), 'dst_port', {filters:f}),
    topTable($('#d-app'), 'application', {filters:f}),
    topTable($('#d-country'), peerCountry, {filters:f}),
    topTable($('#d-asn'), peerASN, {filters:f, fmt:v=>v==='0'?'未知':'AS'+esc(v)}),
    topTable($('#d-proto'), 'protocol', {filters:f}),
  ]);
  box.scrollIntoView({behavior:'smooth', block:'nearest'});
}

async function loadConv(){
  showErr('');
  const q = ast({group_by:['src_ip','dst_ip'], limit:40, metrics:['bytes','packets','flows']});
  let d;
  try { d = await api('/api/v1/query', q); } catch(e){ $('#c-list').innerHTML='<div class="empty">'+esc(e.message)+'</div>'; return; }
  if(!d || !d.rows.length){ $('#c-list').innerHTML='<div class="empty">这段时间没有数据</div>'; return; }
  let h='<table><tr><th>源</th><th>目的</th><th class="num">字节</th><th class="num">包</th><th class="num">流</th></tr><tbody>';
  for(const r of d.rows){
    h+='<tr><td class="mono drill" data-drill="src_ip" data-val="'+esc(r[0])+'">'+esc(r[0])+'</td>'
     + '<td class="mono drill" data-drill="dst_ip" data-val="'+esc(r[1])+'">'+esc(r[1])+'</td>'
     + '<td class="num">'+fmtBytes(r[2])+'</td><td class="num">'+fmtNum(r[3])+'</td>'
     + '<td class="num">'+fmtNum(r[4])+'</td></tr>';
  }
  $('#c-list').innerHTML=h+'</tbody></table>';
  $('#c-list').querySelectorAll('[data-drill]').forEach(n=>n.onclick=()=>drillTo(n.dataset.drill,n.dataset.val));
}

async function loadGeo(){
  showErr('');
  const jobs = [
    topTable($('#g-srcc'),'src_country',{limit:15}),
    topTable($('#g-dstc'),'dst_country',{limit:15}),
    topTable($('#g-srca'),'src_asn',{limit:15,fmt:v=>v==='0'?'未知':'AS'+esc(v)}),
    topTable($('#g-org'),'src_org',{limit:15,fmt:v=>v?esc(v):'<span style="color:var(--dim2)">未知</span>'}),
  ];
  // 城市维度只在有 mmdb 时查 —— 否则查出来全是空字符串一行
  if(FIELDS && FIELDS.groupable.includes('src_city')){
    jobs.push(topTable($('#g-city'),'src_city',{limit:15,
      fmt:v=>v?esc(v):'<span style="color:var(--dim2)">未知</span>'}));
  }
  await Promise.all(jobs);
}

// --- Explorer ---
function addCond(){
  if(!FIELDS) return;
  const d=document.createElement('div');
  d.className='cond';
  const fopts=FIELDS.filterable.map(f=>'<option value="'+esc(f.name)+'" data-ops="'+esc(f.operators.join(','))+'">'+esc(f.name)+'</option>').join('');
  d.innerHTML='<select class="c-field" style="width:150px">'+fopts+'</select>'
    + '<select class="c-op" style="width:120px"></select>'
    + '<input type="text" class="c-val" placeholder="值" style="width:190px">';
  const rm=document.createElement('button'); rm.className='gh'; rm.textContent='删除';
  rm.onclick=()=>d.remove(); d.appendChild(rm);
  const fs=d.querySelector('.c-field'), os=d.querySelector('.c-op');
  const syncOps=()=>{
    const ops=(fs.selectedOptions[0].dataset.ops||'').split(',').filter(Boolean);
    os.innerHTML=ops.map(o=>'<option>'+esc(o)+'</option>').join('');
  };
  fs.onchange=syncOps; syncOps();
  $('#conds').appendChild(d);
}

function buildFilters(){
  const conds=[];
  for(const el of document.querySelectorAll('#conds .cond')){
    const field=el.querySelector('.c-field').value;
    const op=el.querySelector('.c-op').value;
    let val=el.querySelector('.c-val').value.trim();
    if(!val) continue;
    // in / not_in 接受逗号分隔;数字字段转成数字,否则 ClickHouse 类型不匹配
    const meta=FIELDS.filterable.find(f=>f.name===field);
    const num=meta&&meta.kind==='int';
    if(op==='in'||op==='not_in'){
      conds.push({field,operator:op,value:val.split(',').map(s=>num?Number(s.trim()):s.trim())});
    } else {
      conds.push({field,operator:op,value:num?Number(val):val});
    }
  }
  if(!conds.length) return undefined;
  if(conds.length===1) return conds[0];
  return {op:$('#e-logic').value, conditions:conds};
}

function explorerAST(){
  return {time_range:timeRange(), filters:buildFilters(),
    group_by:[$('#e-group').value], metrics:[$('#e-metric').value],
    limit:parseInt($('#e-limit').value)||100};
}

async function runExplore(){
  showErr(''); $('#e-sql').innerHTML='';
  let d;
  try { d = await api('/api/v1/query', explorerAST()); }
  catch(e){ showErr(e.message); $('#e-out').innerHTML=''; return; }
  if(!d) return;
  if(!d.rows.length){ $('#e-out').innerHTML='<div class="empty">没有匹配的数据</div>'; return; }
  let h='<p class="hint">'+d.stats.rows_returned+' 行 · '+d.stats.elapsed_ms+' ms · 表 '+esc(d.stats.table)+'</p>';
  h+='<table><tr>'+d.columns.map(c=>'<th>'+esc(c)+'</th>').join('')+'</tr><tbody>';
  for(const r of d.rows){
    h+='<tr>'+r.map((v,i)=>{
      const c=d.columns[i];
      const cls=(c==='bytes'||c==='packets'||c==='flows'||c.startsWith('observed')||c.startsWith('uniq'))?'num':'mono';
      const disp=c==='bytes'||c==='observed_bytes'?fmtBytes(v):(cls==='num'?fmtNum(v):esc(v));
      return '<td class="'+cls+'">'+disp+'</td>';
    }).join('')+'</tr>';
  }
  $('#e-out').innerHTML=h+'</tbody></table>';
}

async function explainExplore(){
  showErr('');
  try {
    const d = await api('/api/v1/query/explain', explorerAST());
    $('#e-sql').innerHTML='<pre>'+esc(d.sql)+'</pre>';
  } catch(e){ showErr(e.message); }
}

async function loadFields(){
  FIELDS = await api('/api/v1/query/fields');
  if(!FIELDS) return;
  $('#e-group').innerHTML=FIELDS.groupable.map(g=>'<option'+(g==='src_ip'?' selected':'')+'>'+esc(g)+'</option>').join('');
  $('#e-metric').innerHTML=FIELDS.metrics.map(m=>'<option'+(m==='bytes'?' selected':'')+'>'+esc(m)+'</option>').join('');
  if(!document.querySelector('#conds .cond')) addCond();
}

$('#addcond').onclick=addCond;
$('#e-run').onclick=runExplore;
$('#e-explain').onclick=explainExplore;

let SYNC_TIMER = null;

async function loadSources(){
  const d = await api('/api/v1/enrich/sources');
  if(!d) return;
  renderSyncStatus(d.status);

  let h='';
  for(const s of d.sources){
    const kindLabel = {asn:'ASN 类', city:'城市类', city_text:'城市类(中文文本)'}[s.kind]||s.kind;
    h += '<div class="src"><div class="top">'
      + '<span class="nm">'+esc(s.name)+'</span>'
      + '<span class="tag">'+esc(kindLabel)+'</span>'
      + '<span class="lic">'+esc(s.license)+'</span>'
      + '<button class="act" data-sync="'+esc(s.id)+'">同步</button>'
      + '</div>'
      + '<div class="fl">填充字段:'+esc(s.fields)+'</div>'
      + '<div class="nt">'+esc(s.note)+'</div></div>';
  }
  $('#sync-list').innerHTML=h;
  $('#sync-list').querySelectorAll('[data-sync]').forEach(b=>b.onclick=()=>doSync(b.dataset.sync));
}

function renderSyncStatus(st){
  const el = $('#sync-status');
  if(!st || (!st.in_progress && !st.finished_at && !st.error)){ el.innerHTML=''; return; }
  if(st.in_progress){
    el.innerHTML='<p class="hint">正在同步 <b>'+esc(st.source_id)+'</b>… '
      + '下载中,大的库可能要几分钟</p>';
    return;
  }
  if(st.error){
    el.innerHTML='<div class="err" style="display:block">同步 '+esc(st.source_id)
      +' 失败:'+esc(st.error)+'</div>';
    return;
  }
  el.innerHTML='<p class="hint"><span class="ok">✓</span> '+esc(st.source_id)
    +' 已同步:'+fmtNum(st.entries)+' 条记录,'+fmtBytes(st.bytes)+'</p>';
}

async function doSync(id){
  showErr('');
  try{
    await api('/api/v1/enrich/sync', {id});
  }catch(e){ showErr(e.message); return; }
  // 轮询进度。同步是后台跑的 —— city 库几十 MB,在带宽受限的机房里
  // 要几分钟,而反向代理通常 60 秒就切断连接。
  if(SYNC_TIMER) clearInterval(SYNC_TIMER);
  SYNC_TIMER = setInterval(async()=>{
    try{
      const d = await api('/api/v1/enrich/sources');
      if(!d) return;
      renderSyncStatus(d.status);
      if(!d.status.in_progress){
        clearInterval(SYNC_TIMER); SYNC_TIMER=null;
        await loadOverview(); await loadFields();
      }
    }catch(e){ clearInterval(SYNC_TIMER); SYNC_TIMER=null; showErr(e.message); }
  }, 2000);
  await loadSources();
}

$('#mmdbup').onclick=async()=>{
  const f=$('#mmdbfile').files[0];
  if(!f){ showErr('请先选择 .mmdb 文件'); return; }
  showErr('');
  const fd=new FormData(); fd.append('mmdb',f);
  try{
    const r=await fetch('/api/v1/enrich/mmdb',{method:'POST',body:fd});
    const d=await r.json();
    if(!r.ok) throw new Error(d.error||'上传失败');
    await loadOverview(); await loadFields();
    alert('已生效:'+d.path+'(构建于 '+d.build_date+')\n'+d.note);
  }catch(e){ showErr(e.message); }
};

document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x===b));
  document.querySelectorAll('section').forEach(s=>s.classList.toggle('on',s.id==='s-'+b.dataset.t));
  load(b.dataset.t);
});
$('#refresh').onclick=()=>load(current());
$('#range').onchange=()=>load(current());
$('#metric').onchange=()=>load(current());

function current(){ return document.querySelector('nav button.on').dataset.t; }

function load(tab){
  const f={dash:loadDash,hosts:loadHosts,conv:loadConv,geo:loadGeo,
           explore:()=>{},
           settings:async()=>{ await loadOverview(); await loadSources(); }}[tab];
  if(f) Promise.resolve(f()).catch(e=>showErr(e.message));
}

(async()=>{
  try{ await loadOverview(); await loadFields(); await loadDash(); }
  catch(e){ showErr(e.message); }
})();
// 只在 Dashboard 停留时自动刷新 —— 在 Explorer 里刷新会把用户
// 正在编辑的条件冲掉。
setInterval(()=>{ if(current()==='dash'){ loadOverview().catch(()=>{}); loadDash().catch(()=>{}); } }, 30000);
</script>
</body>
</html>
`
