package api

// 登录页。内嵌为字符串常量,不引外部资源:单一二进制、内网部署时
// CDN 拉不到会直接白屏。
const loginHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ntop2ban</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;
 font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
 background:#0f1520;color:#e6edf3}
.card{width:340px;background:#161d29;border:1px solid #232c3b;border-radius:12px;padding:30px}
h1{margin:0 0 2px;font-size:20px;letter-spacing:-.02em}
.sub{margin:0 0 24px;color:#7d8896;font-size:12.5px}
label{display:block;margin:14px 0 6px;font-size:12.5px;color:#9aa5b1}
input{width:100%;padding:9px 11px;background:#0f1520;border:1px solid #2b3546;
 border-radius:6px;font-size:14px;color:#e6edf3}
input:focus{outline:none;border-color:#3d7eff}
button{width:100%;margin-top:22px;padding:10px;border:0;border-radius:6px;
 background:#3d7eff;color:#fff;font-size:14px;font-weight:500;cursor:pointer}
button:hover{background:#5590ff}
.err{margin-top:14px;padding:9px 11px;border-radius:6px;background:#2d1618;
 color:#ff9c9c;font-size:12.5px;display:none}
</style>
</head>
<body>
<div class="card">
  <h1>ntop2ban</h1>
  <p class="sub">Flow Analytics</p>
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
    const r = await fetch('/login', {method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username:document.getElementById('u').value,
                            password:document.getElementById('p').value})});
    if (r.ok) { location.href = '/'; return; }
    const d = await r.json();
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
