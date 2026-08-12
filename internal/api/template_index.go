package api

// Dashboard 与 Explorer。深色主题,图表用 ECharts。
//
// ECharts 与世界地图底图都由 internal/api/static.go 嵌进二进制,从
// /static/ 提供,**不走 CDN** —— ntop2ban 常部署在没有出网的内网机房,
// 一个取不到的 CDN 会让整个界面变成白屏。压缩后合计约 0.4MB。
//
// 早先这些图是手写 SVG 的。换掉的原因不是画不出形状,而是画出来之后
// 缺的都是"看图的人真正要用的东西":悬浮读数、图例开关、局部放大、
// 点击下钻、以及地图。这些每一个自己实现都不难,加在一起就是在重写
// 一个图表库,而且是一个没人测过的图表库。
//
// 所有数据都走 POST /api/v1/query 提交 Query AST。每个卡片、每次下钻
// 都是一次 AST 请求 —— 同一个引擎服务所有视图。
const indexHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ntop2ban</title>
<script src="/static/echarts.min.js"></script>
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

/* 图表容器必须有确定高度:ECharts 按容器实际尺寸画,高度靠内容撑
   的话初始化时量到 0,图就是空白的。 */
.ec{width:100%;height:240px}
.ec.tall{height:320px}
.ec.map{height:420px}
.ec.pie{height:210px}

/* 全局过滤条件。点饼图扇区、点地图国家都往这里加一条,所有卡片的
   查询都会带上 —— 否则点了之后只有被点的那张图变,其他卡片还是全量,
   同一屏上两套口径最容易让人读错。 */
.pills{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 8px;border-radius:12px;
 background:rgba(61,126,255,.16);border:1px solid rgba(61,126,255,.35);
 font-size:11.5px;color:#9fc0ff}
.pill b{font-weight:600;color:#cfe0ff}
.pill x{cursor:pointer;color:#8ab4ff;font-style:normal;line-height:1}
.pill x:hover{color:#fff}

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
      <option value="custom">自定义…</option>
    </select>
    <span id="custom-range" style="display:none;gap:6px;align-items:center">
      <input type="datetime-local" id="from" step="1">
      <span style="color:var(--dim2)">→</span>
      <input type="datetime-local" id="to" step="1">
    </span>
    <select id="metric">
      <option value="bytes">按字节</option>
      <option value="packets">按包数</option>
      <option value="flows">按流数</option>
    </select>
    <button class="act" id="refresh">刷新</button>
    <span class="hint" id="scope" style="color:var(--dim2);font-size:11.5px"></span>
  </div>

  <div class="bar pills" id="pills" style="display:none"></div>

  <section class="on" id="s-dash">
    <div class="kpis" id="kpis"></div>
    <div class="grid g2">
      <div class="panel wide">
        <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
          <h2>流量趋势</h2>
          <select id="ts-dim" style="margin-left:auto;font-size:12px">
            <option value="application" selected>按应用堆叠</option>
            <option value="protocol">按协议堆叠</option>
            <option value="src_country">按源国家堆叠</option>
            <option value="dst_port">按目的端口堆叠</option>
            <option value="">只看总量</option>
          </select>
        </div>
        <p class="hint" id="ts-hint">估算值(已按采样率还原)。拖动下方滑块可放大某一段</p>
        <div id="ts" class="ec tall"></div>
      </div>
      <div class="panel"><h2>Top Talkers(源)</h2><p class="hint">谁发出最多</p><div id="topsrc"></div></div>
      <div class="panel"><h2>Top Destinations(目的)</h2><p class="hint">流量去了哪</p><div id="topdst"></div></div>
      <div class="panel"><h2>应用(按端口推断)</h2><p class="hint">端口推断,不是 DPI 确认</p><div id="topapp" class="ec pie"></div></div>
      <div class="panel"><h2>协议</h2><p class="hint"></p><div id="topproto" class="ec pie"></div></div>
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
    <div class="panel wide" style="margin-bottom:12px">
      <div style="display:flex;align-items:baseline;gap:10px;flex-wrap:wrap">
        <h2>流量地图</h2>
        <select id="map-dir" style="margin-left:auto;font-size:12px">
          <option value="src_country" selected>按源国家</option>
          <option value="dst_country">按目的国家</option>
        </select>
      </div>
      <p class="hint">颜色深浅是该国流量占比(对数刻度)。点一个国家会加成全局过滤条件;滚轮缩放,拖动平移</p>
      <div id="g-map" class="ec map"></div>
    </div>
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
      <div class="bar" style="margin:2px 0 0;padding-top:10px;border-top:1px solid var(--line)">
        <span class="hint" style="margin:0">保存的查询</span>
        <select id="sq-list" style="min-width:210px"><option value="">—</option></select>
        <button class="gh" id="sq-load">加载</button>
        <button class="gh" id="sq-del">删除</button>
        <input type="text" id="sq-name" placeholder="起个名字" style="width:180px;margin-left:14px">
        <button class="act" id="sq-save">保存当前条件</button>
        <span class="hint" id="sq-msg" style="margin:0"></span>
      </div>
      <p class="hint" style="margin:6px 0 0">保存的是"这几个选择"而不是当时那一小时的数据 ——
        下次加载看的是加载那一刻的最新数据(选了自定义区间的除外)</p>
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

// protocol 列存的是 IP 协议号。界面上直接显示 6 和 17 没有意义 ——
// 看图的人要的是 TCP / UDP。过滤仍然用原始数字,只有显示走这张表。
const PROTO = {1:'ICMP',2:'IGMP',6:'TCP',17:'UDP',41:'IPv6',47:'GRE',50:'ESP',
  51:'AH',58:'ICMPv6',89:'OSPF',132:'SCTP'};
function protoLabel(v){ return PROTO[Number(v)] || ('协议 '+v); }
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
//
// RANGE 在每次加载开始时算一次,整屏所有卡片共用。以前是每张卡片各自
// 调一次 timeRange(),于是每张卡片的 to 都差几十毫秒、几张图覆盖的窗口
// 其实不一样 —— 数据量大时"总流量"与各分项加起来对不上,而看图的人
// 只会以为是哪里算错了。
let RANGE = null;

function computeRange(){
  const v = $('#range').value;
  if(v==='custom'){
    const f=$('#from').value, t=$('#to').value;
    if(!f||!t) return {err:'请填写自定义时间范围的起止时间'};
    const from=new Date(f), to=new Date(t);
    if(isNaN(from)||isNaN(to)) return {err:'自定义时间格式无法解析'};
    if(!(to>from)) return {err:'自定义时间范围无效:结束时间必须晚于开始时间'};
    return {from:from.toISOString(), to:to.toISOString(), ms:to-from};
  }
  const n=parseInt(v), u=v.slice(-1);
  const ms = u==='m'?n*6e4 : u==='h'?n*36e5 : n*864e5;
  const to=new Date(), from=new Date(to.getTime()-ms);
  return {from:from.toISOString(), to:to.toISOString(), ms:ms};
}
// refreshRange 返回错误信息(没有错误时返回空)。
function refreshRange(){
  const r = computeRange();
  if(r.err) return r.err;
  RANGE = r;
  return '';
}
function timeRange(){
  if(!RANGE) refreshRange();
  return {from:RANGE.from, to:RANGE.to};
}
function spanMs(){
  if(!RANGE) refreshRange();
  return RANGE.ms;
}
function metric(){ return $('#metric').value; }
function metricLabel(){
  return {bytes:'字节', packets:'包数', flows:'流数'}[metric()]||metric();
}

// --- 全局过滤 ---
//
// 点饼图扇区、点地图国家都往这里加一条,之后每个卡片的查询都带上它。
// 只让被点的那张图变化是更省事的做法,但那样同一屏上就有两套口径,
// 读数对不上时没人分得清是过滤生效了还是数据本身如此。
let GLOBAL = [];

function addFilter(field, value){
  if(GLOBAL.some(c=>c.field===field && String(c.value)===String(value))) return;
  GLOBAL.push({field:field, operator:'eq', value:coerce(field, value)});
  renderPills();
  load(current());
}
function dropFilter(i){ GLOBAL.splice(i,1); renderPills(); load(current()); }

function renderPills(){
  const el=$('#pills');
  if(!GLOBAL.length){ el.style.display='none'; el.innerHTML=''; return; }
  el.style.display='flex';
  el.innerHTML = '<span class="hint" style="margin:0">过滤:</span>'
    + GLOBAL.map((c,i)=>'<span class="pill"><b>'+esc(c.field)+'</b> = '+esc(c.value)
        + ' <x data-drop="'+i+'" title="移除">x</x></span>').join('')
    + '<button class="gh" id="clearpills">清空</button>';
  el.querySelectorAll('[data-drop]').forEach(n=>n.onclick=()=>dropFilter(Number(n.dataset.drop)));
  $('#clearpills').onclick=()=>{ GLOBAL=[]; renderPills(); load(current()); };
}

// coerce 把值转成字段该有的类型。整型字段(端口、ASN)传字符串过去,
// ClickHouse 会因为类型不匹配直接报错。
function coerce(field, v){
  const meta = FIELDS && FIELDS.filterable.find(f=>f.name===field);
  return (meta && meta.kind==='int') ? Number(v) : String(v);
}
function isIntField(field){
  const meta = FIELDS && FIELDS.filterable.find(f=>f.name===field);
  return !!(meta && meta.kind==='int');
}

// andAll 把全局过滤与卡片自己的过滤 AND 在一起。AST 的 Condition 允许
// 嵌套,所以直接塞成子条件即可,不用在前端把树拍平。
function andAll(extra){
  const all = GLOBAL.slice();
  if(extra) all.push(extra);
  if(!all.length) return undefined;
  if(all.length===1) return all[0];
  return {op:'AND', conditions:all};
}

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
  const q = Object.assign({time_range:timeRange(), limit:10, metrics:[metric()]}, o||{});
  const f = andAll(o && o.filters);
  if(f) q.filters = f; else delete q.filters;
  return q;
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
    // 空值统一显示成"(未知)":富化库缺这一条时 label 是空字符串,
    // 直接渲染出来就是一行只有数字、名字那格空白的表,看着像界面坏了。
    // 空值也不给点击 —— 按空字符串过滤只会得到"未知的那一堆",没有意义。
    const blank = String(label)==='';
    const disp = opts.fmt ? opts.fmt(label)
               : (blank ? '<span style="color:var(--dim2)">(未知)</span>' : esc(label));
    // drill 跳到 Hosts 页展开这个主机的构成;filter 只是把它加成全局
    // 过滤条件。两者不能混用一个属性:国家、ASN 这类维度没有"主机详情"
    // 可展开,点过去会是一屏用 country 当 IP 查出来的空表。
    let clickable = '';
    if(blank) clickable = '';
    else if(opts.drill) clickable = ' class="drill" data-drill="'+esc(opts.drill)+'" data-val="'+esc(label)+'"';
    else if(opts.filter) clickable = ' class="drill" data-filter="'+esc(opts.filter)+'" data-val="'+esc(label)+'"';
    h += '<tr><td class="barcell"><span class="fill" style="width:'+pct+'%"></span>'
       + '<span class="txt mono"'+clickable+'>'+disp+'</span></td>'
       + '<td class="num">'+fmtMetric(val)+'</td></tr>';
  }
  el.innerHTML = h+'</tbody></table>';
  el.querySelectorAll('[data-drill]').forEach(n=>n.onclick=()=>drillTo(n.dataset.drill, n.dataset.val));
  el.querySelectorAll('[data-filter]').forEach(n=>n.onclick=()=>addFilter(n.dataset.filter, n.dataset.val));
}

// --- ECharts 基础 ---
//
// 复用实例而不是每次重新 init:Dashboard 每 30 秒自动刷新一次,每 init
// 一次就多一个 canvas 和一组事件监听,而旧的那个不会被回收 —— 界面开
// 一晚上就是几百个实例同时在监听 resize。
const EC = [];

function chart(el){
  let c = echarts.getInstanceByDom(el);
  if(!c){
    el.innerHTML='';  // 可能残留上一次的"没有数据"提示
    c = echarts.init(el);
    EC.push(c);
  }
  return c;
}

function resizeCharts(){ EC.forEach(c=>{ try{ c.resize(); }catch(e){} }); }
window.addEventListener('resize', resizeCharts);

// showEmpty 用文字占位替掉图。必须真的 dispose:只 clear() 的话实例还
// 占着容器,下次要画图时 innerHTML 里的提示文字会叠在 canvas 上面。
function showEmpty(el, msg){
  const c = echarts.getInstanceByDom(el);
  if(c){
    c.dispose();
    const i=EC.indexOf(c); if(i>=0) EC.splice(i,1);
  }
  el.innerHTML = '<div class="empty">'+esc(msg)+'</div>';
}

const TIP = {backgroundColor:'#161d29', borderColor:'#2b3546', borderWidth:1,
  textStyle:{color:'#e6edf3',fontSize:12}, extraCssText:'box-shadow:0 4px 16px rgba(0,0,0,.45)'};

function tsTooltip(ps){
  if(!ps || !ps.length) return '';
  let total=0;
  for(const p of ps) total += Number(p.value[1])||0;
  const items = ps.slice().sort((a,b)=>(Number(b.value[1])||0)-(Number(a.value[1])||0));
  let h='<div style="font-size:11.5px;color:#8b95a3;margin-bottom:5px">'+ts(ps[0].value[0]/1000)+'</div>';
  for(const p of items){
    const v=Number(p.value[1])||0;
    if(!v) continue;   // 补零点占满了图例时的 tooltip,没有信息量
    h+='<div style="display:flex;gap:9px;align-items:center;line-height:1.7">'
     + '<span style="width:8px;height:8px;border-radius:2px;background:'+p.color+'"></span>'
     + '<span style="flex:1">'+esc(p.seriesName)+'</span>'
     + '<b style="font-variant-numeric:tabular-nums">'+fmtMetric(v)+'</b></div>';
  }
  if(items.length>1){
    h+='<div style="margin-top:5px;padding-top:4px;border-top:1px solid #2b3546;'
     + 'display:flex;gap:9px;line-height:1.7"><span style="flex:1;color:#8b95a3">合计</span>'
     + '<b style="font-variant-numeric:tabular-nums">'+fmtMetric(total)+'</b></div>';
  }
  return h;
}

// 时间序列。默认按维度堆叠 —— 一条总量曲线能告诉你"涨了",堆叠能
// 告诉你"是谁涨的",而后者才是看这张图的目的。
async function timeseries(el){
  const ms = spanMs();
  // 桶粒度按跨度选:分钟粒度在 30 天上是 43200 个点,既超 limit 上限
  // 也堆不出可读的图;小时粒度在 15 分钟上只有一个点。
  const interval = ms > 7*864e5 ? 'day' : (ms > 6*36e5 ? 'hour' : 'minute');
  const dim = $('#ts-dim').value;
  $('#ts-hint').textContent = '按' + ({minute:'分钟',hour:'小时',day:'天'}[interval])
    + '聚合的' + metricLabel() + ',估算值(已按采样率还原)。拖动下方滑块放大某一段';

  let series, stacked = !!dim;
  try {
    if(dim){
      // 两步查:先取这段时间的 Top 6,再只对这几个值拉时间序列。
      // 一步 group_by 时间桶 + 维度会把所有取值都带回来 —— 端口维度上
      // 那是几万行,既超 limit 上限,也没人能读懂堆了五十层的面积图。
      const top = await api('/api/v1/query', ast({group_by:[dim], limit:6}));
      if(!top) return;
      const keys = top.rows.map(r=>String(r[0]));
      if(!keys.length){ showEmpty(el,'这段时间没有数据'); return; }
      const d = await api('/api/v1/query', ast({interval:interval, group_by:[dim],
        limit:10000, sort:{field:'ts',desc:false},
        filters:{field:dim, operator:'in', value: isIntField(dim)?keys.map(Number):keys}}));
      if(!d) return;
      if(!d.rows.length){ showEmpty(el,'这段时间没有数据'); return; }
      series = pivot(d.rows, keys, dim==='protocol'?protoLabel:null);
    } else {
      const d = await api('/api/v1/query', ast({interval:interval, limit:10000,
        sort:{field:'ts',desc:false}}));
      if(!d) return;
      if(!d.rows.length){ showEmpty(el,'这段时间没有数据'); return; }
      series = [{name:metricLabel(),
        data:d.rows.map(r=>[Number(r[0])*1000, Number(r[1])||0])}];
    }
  } catch(e){ showEmpty(el, e.message); return; }

  chart(el).setOption({
    color: PAL,
    tooltip: Object.assign({trigger:'axis', formatter:tsTooltip,
      axisPointer:{type:'line', lineStyle:{color:'#3d7eff', width:1, type:'dashed'}}}, TIP),
    legend: stacked ? {top:0, right:8, textStyle:{color:'#8b95a3',fontSize:11},
      itemWidth:9, itemHeight:9, itemGap:14, inactiveColor:'#454f60'} : {show:false},
    grid:{left:66, right:18, top: stacked?30:12, bottom:58},
    xAxis:{type:'time', boundaryGap:false,
      axisLine:{lineStyle:{color:'#2b3546'}}, axisTick:{show:false},
      axisLabel:{color:'#8b95a3', fontSize:10.5,
        formatter:{year:'{yyyy}',month:'{MM}-{dd}',day:'{MM}-{dd}',
          hour:'{MM}-{dd}\n{HH}:{mm}',minute:'{HH}:{mm}',second:'{HH}:{mm}:{ss}'}},
      splitLine:{show:false}},
    yAxis:{type:'value',
      axisLine:{show:false}, axisTick:{show:false},
      axisLabel:{color:'#8b95a3', fontSize:10.5, formatter:v=>fmtMetric(v)},
      splitLine:{lineStyle:{color:'#232c3b'}}},
    // 局部放大:采样数据里最值得看的往往是某一分钟的尖峰,而整段视图
    // 里它只有一两个像素宽。
    dataZoom:[{type:'inside', zoomOnMouseWheel:true, moveOnMouseMove:true},
      {type:'slider', height:16, bottom:12, borderColor:'#2b3546',
       backgroundColor:'rgba(0,0,0,0)', fillerColor:'rgba(61,126,255,.14)',
       dataBackground:{lineStyle:{color:'#2b3546'}, areaStyle:{color:'#1b2230'}},
       handleStyle:{color:'#3d7eff', borderColor:'#3d7eff'},
       textStyle:{color:'#5f6977', fontSize:10}}],
    series: series.map(sr=>({name:sr.name, type:'line',
      stack: stacked?'总量':undefined,
      showSymbol:false, symbol:'circle', symbolSize:5,
      lineStyle:{width: stacked?1:1.7},
      areaStyle:{opacity: stacked?0.8:0.26},
      emphasis:{focus:'series'},
      data:sr.data}))
  }, true);
}

// pivot 把 [ts, 维度值, 指标] 的长表转成每个维度值一条序列。
//
// 缺失的时间点必须补 0 而不是留空:ECharts 的堆叠是按数据下标相加的,
// 不是按 x 值对齐。各条序列点数不一致时,堆出来的高度会张冠李戴 ——
// 图还是好看的,数字全是错的。
function pivot(rows, keys, lbl){
  const tset = new Set(), byKey = new Map();
  for(const k of keys) byKey.set(k, new Map());
  for(const r of rows){
    const t=Number(r[0]), k=String(r[1]);
    tset.add(t);
    const m=byKey.get(k);
    if(m) m.set(t, (m.get(t)||0) + (Number(r[2])||0));
  }
  const tl=Array.from(tset).sort((a,b)=>a-b);
  return keys.map(k=>{
    const m=byKey.get(k);
    const name = lbl ? String(lbl(k)) : (k===''?'(未知)':k);
    return {name: name, data: tl.map(t=>[t*1000, m.get(t)||0])};
  });
}

// 甜甜圈:协议 / 应用构成。点扇区加成全局过滤条件。
async function donut(el, groupBy, opts){
  let d;
  try { d = await api('/api/v1/query', ast({group_by:[groupBy], limit:8})); }
  catch(e){ showEmpty(el, e.message); return; }
  if(!d) return;
  if(!d.rows.length){ showEmpty(el,'这段时间没有数据'); return; }

  // raw 与 name 分开存:空值显示成"(未知)"更好读,但点击时要拿原值
  // 去过滤 —— 拿显示名去查会查不到任何东西。
  const lbl = (opts && opts.label) || (v=>v||'(未知)');
  const items = d.rows.map(r=>({raw:String(r[0]), name:String(lbl(String(r[0]))),
    value:Number(r[1])||0}));
  const total = items.reduce((a,b)=>a+b.value,0);

  const c = chart(el);
  c.setOption({
    color: PAL,
    tooltip: Object.assign({trigger:'item',
      formatter:p=>esc(p.name)+'<br><b>'+fmtMetric(p.value)+'</b> · '+p.percent+'%'}, TIP),
    legend:{type:'scroll', orient:'vertical', right:4, top:6, bottom:6,
      textStyle:{color:'#8b95a3', fontSize:11}, itemWidth:9, itemHeight:9},
    title:{text:fmtMetric(total), subtext:'合计', left:'27%', top:'40%',
      textAlign:'center', textStyle:{color:'#e6edf3',fontSize:15,fontWeight:600},
      subtextStyle:{color:'#8b95a3',fontSize:11}},
    series:[{type:'pie', radius:['54%','80%'], center:['27%','52%'],
      avoidLabelOverlap:true, label:{show:false}, labelLine:{show:false},
      itemStyle:{borderColor:'#161d29', borderWidth:1.5},
      emphasis:{scale:true, scaleSize:4},
      data:items}]
  }, true);

  // off 再 on:不然每次刷新都叠一个监听,点一次会触发 N 遍加过滤。
  c.off('click');
  c.on('click', p=>{
    const it = items[p.dataIndex];
    if(it && it.raw!=='') addFilter(groupBy, it.raw);
  });
}

// 流量地图。底图 feature 名就是 ISO alpha-2 码,与查询结果的 country
// 取值直接对齐(理由见 tools/genworld/main.go)。
let MAP_READY = null;

function ensureMap(){
  // 底图 0.4MB,只在真的要画地图时才取,而且只取一次。放在页面加载时
  // 拉会让 Dashboard 第一屏白等这 0.4MB —— 而多数人根本不点地图页。
  if(!MAP_READY){
    MAP_READY = fetch('/static/world.json')
      .then(r=>{ if(!r.ok) throw new Error('底图加载失败 HTTP '+r.status); return r.json(); })
      .then(geo=>{
        echarts.registerMap('world', geo);
        const zh={};
        for(const f of geo.features) zh[f.properties.name]=f.properties.zh||f.properties.en||f.properties.name;
        return zh;
      })
      .catch(e=>{ MAP_READY=null; throw e; });
  }
  return MAP_READY;
}

async function geoMap(el){
  const field = $('#map-dir').value;
  let zh, d;
  try {
    zh = await ensureMap();
    d = await api('/api/v1/query', ast({group_by:[field], limit:250}));
  } catch(e){ showEmpty(el, e.message); return; }
  if(!d) return;

  const rows = d.rows.map(r=>({name:String(r[0]), value:Number(r[1])||0}))
                     .filter(r=>r.name && r.name.length===2);
  if(!rows.length){ showEmpty(el,'这段时间没有带国家信息的数据(需要 ip2asn 或城市库)'); return; }
  const vals = rows.map(r=>r.value);
  const max = Math.max.apply(null, vals) || 1;
  const min = Math.min.apply(null, vals);

  // 对数刻度。流量的国家分布几乎总是一个国家占九成,线性刻度下其余
  // 全是同一种颜色 —— 图上只能看出"最大的那个是谁",而那本来就写在
  // 旁边的榜单里了。
  const lg = rows.map(r=>({name:r.name, value:Math.log10(r.value+1), raw:r.value}));

  chart(el).setOption({
    tooltip: Object.assign({trigger:'item',
      formatter:p=>{
        const n = zh[p.name]||p.name;
        if(p.data===undefined || p.data===null) return esc(n)+'<br><span style="color:#8b95a3">这段时间没有流量</span>';
        return '<b>'+esc(n)+'</b> ('+esc(p.name)+')<br>'+fmtMetric(p.data.raw)
             + '<br><span style="color:#8b95a3;font-size:11px">点击加成过滤条件</span>';
      }}, TIP),
    // 色标要显示出来。不显示的话,一屏橙色只能看出"这几个国家有流量",
    // 看不出彼此差几个数量级 —— 而这正是用对数刻度的目的。两端的文字
    // 直接写成人能读的流量值,因为刻度值本身是 log10 后的数字。
    // 色标下端取实际最小值而不是 0:数据里最少的国家往往也有几 MB,
    // 从 0 起算的话所有国家都挤在色带最上面那一小段,整张图一个颜色,
    // 对数刻度就白做了。只有一个国家时(min==max)人为拉开一档,
    // 否则 min==max 会让 ECharts 整块涂成同一端的颜色。
    visualMap:{show:true, left:14, bottom:16, itemHeight:90,
      min:Math.log10(min+1) - (min===max?1:0), max:Math.log10(max+1),
      text:[fmtMetric(max), fmtMetric(min)],
      textStyle:{color:'#8b95a3', fontSize:11},
      inRange:{color:['#1b2a44','#22508f','#3d7eff','#00c2d7','#e8a33d']}},
    series:[{type:'map', map:'world', roam:true, zoom:1.15,
      center:[10,20],
      itemStyle:{areaColor:'#1a212e', borderColor:'#2b3546', borderWidth:.6},
      emphasis:{label:{show:false}, itemStyle:{areaColor:'#5590ff'}},
      select:{disabled:true},
      nameProperty:'name',
      data:lg}]
  }, true);

  const c = chart(el);
  c.off('click');
  c.on('click', p=>{ if(p.data) addFilter(field, p.name); });
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
    donut($('#topproto'),'protocol',{label:protoLabel}),
    topTable($('#topport'),'dst_port',{filter:'dst_port'}),
    topTable($('#topasn'),'src_asn',{filter:'src_asn',fmt:v=>v==='0'?'<span style="color:var(--dim2)">未知</span>':'AS'+esc(v)}),
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
    topTable($('#d-proto'), 'protocol', {filters:f, fmt:protoLabel}),
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
    geoMap($('#g-map')),
    topTable($('#g-srcc'),'src_country',{limit:15,filter:'src_country'}),
    topTable($('#g-dstc'),'dst_country',{limit:15,filter:'dst_country'}),
    topTable($('#g-srca'),'src_asn',{limit:15,filter:'src_asn',fmt:v=>v==='0'?'未知':'AS'+esc(v)}),
    topTable($('#g-org'),'src_org',{limit:15,filter:'src_org'}),
  ];
  // 城市维度只在有 mmdb 时查 —— 否则查出来全是空字符串一行
  if(FIELDS && FIELDS.groupable.includes('src_city')){
    jobs.push(topTable($('#g-city'),'src_city',{limit:15,
      fmt:v=>v?esc(v):'<span style="color:var(--dim2)">未知</span>'}));
  }
  await Promise.all(jobs);
}

// --- Explorer ---
// addCond 加一行过滤条件。preset 非空时按它预填(加载保存的查询用)。
function addCond(preset){
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

  if(preset && preset.field){
    fs.value = preset.field;
    syncOps();               // 换字段会换掉可用运算符,必须先同步再设 operator
    if(preset.operator) os.value = preset.operator;
    const v = preset.value;
    // in / not_in 存的是数组,界面上是一个逗号分隔的输入框
    d.querySelector('.c-val').value = Array.isArray(v) ? v.join(',') : String(v==null?'':v);
  }

  $('#conds').appendChild(d);
}

// buildLeaves 读出 Query Builder 里的叶子条件。
//
// 与 buildFilters 分开是因为保存查询要存的是这份平铺列表:存组装好的
// 条件树的话,加载时还得把树拆回一行行界面控件,而界面本来就只能表达
// 平铺结构 —— 存了树反而要写一个只用来读自己写出来的树的解析器。
function buildLeaves(){
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
  return conds;
}

function buildFilters(){
  const conds = buildLeaves();
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
  // 统计信息的字段名是 statistics(见 /api/v1/query 的响应),不是 stats。
  // 写错的话这一行会抛 "reading 'rows_returned' of undefined",连带下面
  // 整张结果表都不渲染 —— 表现为 Explorer 点查询后一片空白、没有报错。
  const st = d.statistics || {};
  let h='<p class="hint">'+fmtNum(st.rows_returned!==undefined?st.rows_returned:d.rows.length)
      + ' 行 · '+(st.elapsed_ms||0)+' ms · 表 '+esc(st.table||'—')+'</p>';
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

// --- 保存查询 ---
let SAVED = [];

function sqMsg(m, bad){
  const el=$('#sq-msg');
  el.textContent=m||'';
  el.style.color = bad ? '#ff9c9c' : 'var(--green)';
}

async function loadSaved(){
  let d;
  try { d = await api('/api/v1/queries'); } catch(e){ sqMsg(e.message, true); return; }
  if(!d) return;
  SAVED = d.queries || [];
  $('#sq-list').innerHTML = '<option value="">—</option>'
    + SAVED.map((q,i)=>'<option value="'+i+'">'+esc(q.name)+'</option>').join('');
}

async function saveQuery(){
  const name = $('#sq-name').value.trim();
  if(!name){ sqMsg('请先起个名字', true); return; }
  const body = {name:name, range:$('#range').value,
    metric:$('#e-metric').value, group_by:$('#e-group').value,
    limit:parseInt($('#e-limit').value)||100,
    logic:$('#e-logic').value, filters:buildLeaves()};
  // 只有真的选了自定义区间才带绝对时间。不然把上次填过的残留值一起
  // 存进去,加载时就会拿一个用户没选过的区间去查。
  if(body.range==='custom'){ body.from=$('#from').value; body.to=$('#to').value; }
  try { await api('/api/v1/queries/save', body); }
  catch(e){ sqMsg(e.message, true); return; }
  await loadSaved();
  const i = SAVED.findIndex(q=>q.name===name);
  if(i>=0) $('#sq-list').value=String(i);
  sqMsg('已保存');
}

async function loadSavedQuery(){
  const i = $('#sq-list').value;
  if(i==='') { sqMsg('先在左边选一条', true); return; }
  const q = SAVED[Number(i)];
  if(!q) return;

  $('#range').value = q.range;
  const custom = q.range==='custom';
  $('#custom-range').style.display = custom ? 'inline-flex' : 'none';
  if(custom){ $('#from').value=q.from||''; $('#to').value=q.to||''; }
  $('#e-metric').value = q.metric;
  $('#e-group').value = q.group_by;
  $('#e-limit').value = q.limit;
  $('#e-logic').value = q.logic||'AND';
  $('#sq-name').value = q.name;

  $('#conds').innerHTML='';
  for(const c of (q.filters||[])) addCond(c);
  if(!(q.filters||[]).length) addCond();

  sqMsg('已加载 ' + q.name);
  const err = refreshRange();
  if(err){ showErr(err); return; }
  await runExplore();
}

async function delSavedQuery(){
  const i = $('#sq-list').value;
  if(i==='') { sqMsg('先在左边选一条', true); return; }
  const q = SAVED[Number(i)];
  if(!q) return;
  if(!confirm('删除保存的查询 "'+q.name+'"?')) return;
  try { await api('/api/v1/queries/delete', {name:q.name}); }
  catch(e){ sqMsg(e.message, true); return; }
  await loadSaved();
  sqMsg('已删除 ' + q.name);
}

$('#sq-save').onclick=saveQuery;
$('#sq-load').onclick=()=>loadSavedQuery().catch(e=>sqMsg(e.message,true));
$('#sq-del').onclick=()=>delSavedQuery().catch(e=>sqMsg(e.message,true));

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
$('#metric').onchange=()=>load(current());
$('#ts-dim').onchange=()=>{ if(!refreshRange()) timeseries($('#ts')); };
$('#map-dir').onchange=()=>{ if(!refreshRange()) geoMap($('#g-map')); };

// 切到"自定义…"时把两个输入框预填成当前区间,而不是留空 —— 从当前
// 看到的范围往两边挪一点是最常见的用法,让人从零填两个完整时间戳
// 只是在制造工作量。
$('#range').onchange=()=>{
  const custom = $('#range').value==='custom';
  $('#custom-range').style.display = custom ? 'inline-flex' : 'none';
  if(custom){
    if(!$('#from').value || !$('#to').value){
      const r = RANGE || computeRange();
      if(r && !r.err){ $('#from').value=localInput(r.from); $('#to').value=localInput(r.to); }
    }
    return;  // 等用户填完再查,不要拿半个区间去查
  }
  load(current());
};
$('#from').onchange=()=>load(current());
$('#to').onchange=()=>load(current());

// localInput 把 ISO 时间转成 datetime-local 输入框要的本地时间格式。
// 直接截 ISO 字符串是错的 —— 那是 UTC,在 UTC+8 会把区间整体挪 8 小时。
//
// 只到分钟:datetime-local 默认 step 是 60 秒,带秒的值会让浏览器多显示
// 一个秒数输入框,而这里的秒本来就只是"切到自定义时的那一瞬间",没意义。
function localInput(iso){
  const d=new Date(iso), p=n=>String(n).padStart(2,'0');
  return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())
    +'T'+p(d.getHours())+':'+p(d.getMinutes());
}

function current(){ return document.querySelector('nav button.on').dataset.t; }

function load(tab){
  const err = refreshRange();
  if(err){ showErr(err); return; }
  const f={dash:loadDash,hosts:loadHosts,conv:loadConv,geo:loadGeo,
           explore:()=>{},
           settings:async()=>{ await loadOverview(); await loadSources(); }}[tab];
  if(!f) return;
  Promise.resolve(f())
    // 隐藏的 section 宽度是 0,在里面初始化的图会被画成一条线。
    // 切过来渲染完统一 resize 一次,比给每张图各自监听可见性简单可靠。
    .then(resizeCharts)
    .catch(e=>showErr(e.message));
}

(async()=>{
  try{
    refreshRange();
    await loadOverview();
    await loadFields();   // 必须在任何查询之前:coerce/isIntField 靠它判断字段类型
    await loadSaved();
    await loadDash();
    resizeCharts();
  } catch(e){ showErr(e.message); }
})();
// 只在 Dashboard 停留时自动刷新 —— 在 Explorer 里刷新会把用户
// 正在编辑的条件冲掉。
setInterval(()=>{
  if(current()!=='dash') return;
  // 自定义区间是固定的绝对时间,自动刷新只会反复查同一段数据 —— 白费
  // 一次查询,还会把用户刚拖出来的缩放视图重置掉。
  if($('#range').value==='custom') return;
  if(refreshRange()) return;
  loadOverview().catch(()=>{});
  loadDash().catch(()=>{});
}, 30000);
</script>
</body>
</html>
`
