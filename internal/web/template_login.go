package web

// 页面模板。刻意不用外部前端框架、不引入 npm 构建:ntop2ban 是单一
// 二进制,HTML/CSS/JS 全部内嵌为字符串常量,`go build` 一步出可运行的
// 程序。图表用 SVG 手绘,不拉 ECharts —— pingping 那份 echarts.min.js
// 有 1MB,嵌进来会让二进制大出一截,而这里要画的图(时间序列折线、
// 排行榜)用几十行 SVG 就够。

const loginHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ntop2ban 登录</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"PingFang SC","Microsoft YaHei",sans-serif;
  background:#f7f8fa;color:#1f2933}
.card{width:340px;background:#fff;border:1px solid #e4e7eb;border-radius:10px;padding:28px}
h1{margin:0 0 4px;font-size:20px;letter-spacing:-.01em}
.sub{margin:0 0 22px;color:#7b8794;font-size:13px}
label{display:block;margin:14px 0 5px;font-size:13px;color:#52606d}
input{width:100%;padding:9px 11px;border:1px solid #cbd2d9;border-radius:6px;font-size:14px}
input:focus{outline:2px solid #2f6feb33;border-color:#2f6feb}
button{width:100%;margin-top:20px;padding:10px;border:0;border-radius:6px;
  background:#1f2933;color:#fff;font-size:14px;cursor:pointer}
button:hover{background:#323f4b}
.err{margin-top:14px;padding:9px 11px;border-radius:6px;background:#fdf2f2;
  color:#a61b1b;font-size:13px;display:none}
</style>
</head>
<body>
<div class="card">
  <h1>ntop2ban</h1>
  <p class="sub">Watch the Top, Ban the Bad.</p>
  <form id="f">
    <label for="u">用户名</label>
    <input id="u" autocomplete="username" autofocus>
    <label for="p">密码</label>
    <input id="p" type="password" autocomplete="current-password">
    <button type="submit">登录</button>
  </form>
  <div class="err" id="e"></div>
</div>
<script>
document.getElementById('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const e = document.getElementById('e');
  e.style.display = 'none';
  try {
    const r = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        username: document.getElementById('u').value,
        password: document.getElementById('p').value
      })
    });
    const d = await r.json();
    if (r.ok) { location.href = '/'; return; }
    e.textContent = d.error || '登录失败';
    e.style.display = 'block';
  } catch (err) {
    e.textContent = '网络错误:' + err.message;
    e.style.display = 'block';
  }
});
</script>
</body>
</html>
`
