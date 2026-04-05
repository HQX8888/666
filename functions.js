// ==============================================
//  【唯一需要修改的配置区】填你自己的Hi168信息
// ==============================================
const CONFIG = {
  // Hi168 S3固定配置，这3项不用改
  s3: {
    endpoint: "https://s3.hi168.com",
    region: "us-east-1",
    // 下面3项填你自己的Hi168信息
    accessKeyId: "D1AASIIKMSR8GXRD5EQM",
    secretAccessKey: "WltIDXSaMbyl8ILAaWJTsPx9Cb8zFcPYA6kymMvr",
    bucket: "6666",
  },
  // 网盘访问密码，自己设置
  accessPassword: "123456",
  // Cookie名称，不用改
  cookieName: "hi168_pages_netdisk",
  // 分享链接有效期（秒），默认1小时
  shareExpire: 3600,
};
// ==============================================
//  配置区结束，下面的代码不要修改
// ==============================================

// ------------------------------
// 核心路由入口
// ------------------------------
export async function handleRequest(request) {
  // 100%兼容的URL解析，彻底解决Unable to parse URL报错
  const url = new URL(request.url, "https://" + request.headers.get("host"));
  const path = url.pathname;

  // 登录页面
  if (path === "/login") {
    if (request.method === "POST") {
      const formData = await request.formData();
      const inputPassword = formData.get("password")?.toString() || "";
      if (inputPassword === CONFIG.accessPassword) {
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `${CONFIG.cookieName}=${CONFIG.accessPassword}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`,
          }
        });
      }
      return renderLoginPage("密码错误，请重新输入");
    }
    return renderLoginPage();
  }

  // 退出登录
  if (path === "/logout") {
    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/login",
        "Set-Cookie": `${CONFIG.cookieName}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      }
    });
  }

  // 鉴权拦截，未登录跳登录页
  const isAuth = checkAuth(request);
  if (!isAuth) return Response.redirect("/login", 302);

  // 首页：文件列表
  if (path === "/") {
    const listResult = await listFiles();
    return renderIndexPage(listResult.files, listResult.error);
  }

  // API：获取上传预签名链接
  if (path === "/api/upload-url" && request.method === "GET") {
    const fileName = url.searchParams.get("name") || "";
    if (!fileName) return jsonResponse({ success: false, error: "文件名不能为空" }, 400);
    try {
      const uploadUrl = await createSignedUrl("PUT", fileName, 1800);
      return jsonResponse({ success: true, uploadUrl });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message }, 500);
    }
  }

  // API：获取分享链接
  if (path === "/api/share" && request.method === "GET") {
    const fileName = url.searchParams.get("name") || "";
    if (!fileName) return jsonResponse({ success: false, error: "文件名不能为空" }, 400);
    try {
      const shareUrl = await createSignedUrl("GET", fileName, CONFIG.shareExpire);
      return jsonResponse({ success: true, shareUrl });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message }, 500);
    }
  }

  // API：删除文件
  if (path === "/api/delete" && request.method === "POST") {
    try {
      const body = await request.json();
      const fileName = body.name || "";
      if (!fileName) return jsonResponse({ success: false, error: "文件名不能为空" }, 400);
      await deleteFile(fileName);
      return jsonResponse({ success: true });
    } catch (err) {
      return jsonResponse({ success: false, error: err.message }, 500);
    }
  }

  // 下载文件跳转
  if (path.startsWith("/download/")) {
    const fileName = path.slice(10);
    if (!fileName) return Response.redirect("/", 302);
    try {
      const downloadUrl = await createSignedUrl("GET", fileName, 3600);
      return Response.redirect(downloadUrl, 302);
    } catch (err) {
      return new Response("下载失败：" + err.message, { status: 500 });
    }
  }

  // 404页面
  return new Response("页面不存在", { status: 404 });
}

// ------------------------------
// 鉴权工具
// ------------------------------
function checkAuth(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.includes(`${CONFIG.cookieName}=${CONFIG.accessPassword}`);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

// ------------------------------
// Hi168 S3 AWS V4签名实现（100%兼容）
// ------------------------------
async function createSignedUrl(method, fileName, expiresIn = 3600) {
  const host = `${CONFIG.s3.bucket}.${CONFIG.s3.endpoint.replace("https://", "")}`;
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const service = "s3";
  const algorithm = "AWS4-HMAC-SHA256";

  const credentialScope = `${dateStamp}/${CONFIG.s3.region}/${service}/aws4_request`;
  const canonicalUri = `/${encodeURIComponent(fileName).replace(/%2F/g, "/")}`;
  const canonicalQuery = [
    `X-Amz-Algorithm=${algorithm}`,
    `X-Amz-Credential=${encodeURIComponent(`${CONFIG.s3.accessKeyId}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    `X-Amz-Expires=${expiresIn}`,
    `X-Amz-SignedHeaders=host`,
  ].join("&");

  const canonicalHeaders = `host:${host}\n`;
  const payloadHash = "UNSIGNED-PAYLOAD";
  const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQuery}\n${canonicalHeaders}\nhost\n${payloadHash}`;

  const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${await sha256Hex(canonicalRequest)}`;
  const signingKey = await getSignatureKey(CONFIG.s3.secretAccessKey, dateStamp, CONFIG.s3.region, service);
  const signature = Array.from(new Uint8Array(await hmacSha256(signingKey, stringToSign)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  const finalQuery = `${canonicalQuery}&X-Amz-Signature=${signature}`;
  return `https://${host}${canonicalUri}?${finalQuery}`;
}

async function getSignatureKey(secretKey, dateStamp, region, service) {
  const kDate = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`AWS4${secretKey}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const kRegionBuf = await hmacSha256(kDate, dateStamp);
  const kRegion = await crypto.subtle.importKey("raw", kRegionBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const kServiceBuf = await hmacSha256(kRegion, region);
  const kService = await crypto.subtle.importKey("raw", kServiceBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const kSigningBuf = await hmacSha256(kService, "aws4_request");
  return await crypto.subtle.importKey("raw", kSigningBuf, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function hmacSha256(key, data) {
  return await crypto.subtle.sign(
    { name: "HMAC", hash: "SHA-256" },
    key,
    new TextEncoder().encode(data)
  );
}

async function sha256Hex(data) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ------------------------------
// S3核心操作
// ------------------------------
async function listFiles() {
  try {
    const listUrl = await createSignedUrl("GET", "", 900);
    const response = await fetch(listUrl + "&list-type=2&max-keys=1000");
    if (!response.ok) throw new Error(`Hi168接口返回错误：${response.status}`);
    const xmlText = await response.text();
    
    // 解析XML文件列表
    const files = [];
    const contentRegex = /<Contents>([\s\S]*?)<\/Contents>/g;
    let match;
    while ((match = contentRegex.exec(xmlText)) !== null) {
      const content = match[1];
      const key = content.match(/<Key>(.*?)<\/Key>/)?.[1] || "";
      const size = parseInt(content.match(/<Size>(.*?)<\/Size>/)?.[1] || "0");
      const lastModified = content.match(/<LastModified>(.*?)<\/LastModified>/)?.[1] || "";
      if (key && !key.endsWith("/")) {
        files.push({ name: key, size, lastModified });
      }
    }
    return { success: true, files };
  } catch (err) {
    return { success: false, files: [], error: err.message };
  }
}

async function deleteFile(fileName) {
  const deleteUrl = await createSignedUrl("DELETE", fileName);
  const response = await fetch(deleteUrl, { method: "DELETE" });
  if (!response.ok) throw new Error(`删除失败：${response.status}`);
  return true;
}

// ------------------------------
// 页面渲染
// ------------------------------
function renderLoginPage(error = "") {
  const errorHtml = error ? `<div class="error">${error}</div>` : "";
  return new Response(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hi168网盘-登录</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0a0a0a;color:#f0f0f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;}
.login-box{width:100%;max-width:400px;background:#141414;border:1px solid #2a2a2a;border-radius:12px;padding:32px 24px;box-shadow:0 8px 32px rgba(0,0,0,0.3);}
.login-box h1{font-size:22px;font-weight:600;text-align:center;margin-bottom:24px;color:#fff;}
.error{color:#ff4d4f;background:rgba(255,77,79,0.1);border:1px solid rgba(255,77,79,0.3);border-radius:6px;padding:10px 12px;margin-bottom:16px;font-size:14px;}
.form-group{margin-bottom:20px;}
.form-group label{display:block;font-size:14px;color:#aaa;margin-bottom:8px;}
.form-group input{width:100%;height:44px;background:#1e1e1e;border:1px solid #333;border-radius:8px;padding:0 12px;color:#fff;font-size:15px;outline:none;transition:border 0.2s;}
.form-group input:focus{border-color:#00bfa5;}
.submit-btn{width:100%;height:44px;background:#00bfa5;color:#000;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:opacity 0.2s;}
.submit-btn:hover{opacity:0.9;}
</style>
</head>
<body>
<div class="login-box">
  <h1>Hi168 网盘</h1>
  ${errorHtml}
  <form method="POST" action="/login">
    <div class="form-group">
      <label>访问密码</label>
      <input type="password" name="password" placeholder="请输入网盘密码" required autocomplete="off">
    </div>
    <button type="submit" class="submit-btn">进入网盘</button>
  </form>
</div>
</body>
</html>
  `, {
    headers: { "Content-Type": "text/html; charset=UTF-8" },
    status: error ? 401 : 200
  });
}

function renderIndexPage(files = [], error = "") {
  const errorHtml = error ? `<div class="error">Hi168连接失败：${error}</div>` : "";
  let fileHtml = "";
  if (files.length === 0) {
    fileHtml = `<tr><td colspan="5" class="empty">当前目录暂无文件</td></tr>`;
  } else {
    files.forEach(file => {
      const size = formatSize(file.size);
      const time = formatTime(file.lastModified);
      fileHtml += `
<tr>
  <td><span class="file-icon">📄</span><span class="file-name">${file.name}</span></td>
  <td class="file-size">${size}</td>
  <td class="file-time">${time}</td>
  <td class="file-actions">
    <button class="btn btn-primary" onclick="downloadFile('${file.name}')">下载</button>
    <button class="btn btn-primary" onclick="shareFile('${file.name}')">分享</button>
    <button class="btn btn-danger" onclick="deleteFile('${file.name}')">删除</button>
  </td>
</tr>
      `;
    });
  }

  return new Response(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hi168 网盘</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
:root{--bg:#0a0a0a;--panel:#141414;--border:#2a2a2a;--primary:#00bfa5;--text:#f0f0f0;--text-secondary:#aaa;--danger:#ff4d4f;}
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:20px;}
.container{max-width:1400px;margin:0 auto;}
.header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border);}
.header h1{font-size:24px;font-weight:600;}
.header-actions{display:flex;align-items:center;gap:12px;}
.btn{height:38px;padding:0 16px;border-radius:8px;border:1px solid var(--border);background:var(--panel);color:var(--text);font-size:14px;cursor:pointer;transition:all 0.2s;display:inline-flex;align-items:center;gap:6px;text-decoration:none;}
.btn:hover{border-color:var(--primary);}
.btn.btn-primary{background:var(--primary);color:#000;border-color:var(--primary);font-weight:600;}
.btn.btn-danger{border-color:var(--danger);color:var(--danger);}
.btn.btn-danger:hover{background:var(--danger);color:#fff;}
.error{color:#ff4d4f;background:rgba(255,77,79,0.1);border:1px solid rgba(255,77,79,0.3);border-radius:6px;padding:10px 12px;margin-bottom:16px;}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px;flex-wrap:wrap;}
.upload-area{display:flex;gap:8px;align-items:center;}
#file-input{display:none;}
.progress-bar{position:fixed;top:0;left:0;width:100%;height:3px;background:var(--primary);transform:scaleX(0);transform-origin:left;transition:transform 0.2s ease;z-index:9999;}
.file-table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;}
.file-table thead{background:#1a1a1a;}
.file-table th{text-align:left;padding:14px 16px;font-size:14px;font-weight:600;color:var(--text-secondary);border-bottom:1px solid var(--border);}
.file-table td{padding:12px 16px;border-bottom:1px solid var(--border);font-size:14px;}
.file-table tbody tr:last-child td{border-bottom:none;}
.file-table tbody tr:hover{background:#1a1a1a;}
.file-icon{font-size:20px;margin-right:10px;}
.file-name{vertical-align:middle;}
.file-size,.file-time{color:var(--text-secondary);white-space:nowrap;}
.file-actions{display:flex;gap:6px;flex-wrap:wrap;white-space:nowrap;}
.empty{text-align:center;padding:40px 20px;color:var(--text-secondary);}
.mask{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);display:none;align-items:center;justify-content:center;z-index:9999;}
.mask.active{display:flex;}
.mask-box{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:24px;max-width:400px;width:100%;}
</style>
</head>
<body>
<div class="progress-bar" id="progress"></div>
<div class="mask" id="mask">
  <div class="mask-box">
    <h3 id="mask-title">操作中</h3>
    <p id="mask-text" style="margin-top:10px;color:var(--text-secondary);">请稍候...</p>
  </div>
</div>

<div class="container">
  <div class="header">
    <h1>Hi168 网盘</h1>
    <div class="header-actions">
      <button class="btn" onclick="location.reload()">🔄 刷新</button>
      <a href="/logout" class="btn btn-danger">退出登录</a>
    </div>
  </div>

  ${errorHtml}

  <div class="toolbar">
    <div class="upload-area">
      <label for="file-input" class="btn btn-primary">📤 上传文件</label>
      <input id="file-input" type="file" multiple>
    </div>
  </div>

  <table class="file-table">
    <thead>
      <tr>
        <th>文件名</th>
        <th>大小</th>
        <th>修改时间</th>
        <th>操作</th>
      </tr>
    </thead>
    <tbody>
      ${fileHtml}
    </tbody>
  </table>
</div>

<script>
const progress = document.getElementById("progress");
const mask = document.getElementById("mask");
const maskTitle = document.getElementById("mask-title");
const maskText = document.getElementById("mask-text");

// 显示/隐藏加载框
function showMask(title, text) {
  maskTitle.innerText = title;
  maskText.innerText = text;
  mask.classList.add("active");
}
function hideMask() {
  mask.classList.remove("active");
}

// 格式化文件大小
function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(2) + " " + sizes[i];
}

// 格式化时间
function formatTime(dateStr) {
  return new Date(dateStr).toLocaleString("zh-CN");
}

// 上传文件
document.getElementById("file-input").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files);
  if (files.length === 0) return;

  let success = 0;
  let fail = 0;
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    progress.style.transform = `scaleX(${(i / files.length)})`;
    try {
      const res = await fetch(`/api/upload-url?name=${encodeURIComponent(file.name)}`);
      const data = await res.json();
      if (!data.success) throw new Error(data.error);
      await fetch(data.uploadUrl, { method: "PUT", body: file });
      success++;
    } catch (err) {
      console.error("上传失败", err);
      fail++;
    }
  }
  progress.style.transform = "scaleX(1)";
  setTimeout(() => {
    progress.style.transform = "scaleX(0)";
    alert(`上传完成：成功${success}个，失败${fail}个`);
    location.reload();
  }, 300);
});

// 下载文件
function downloadFile(name) {
  window.open(`/download/${encodeURIComponent(name)}`, "_blank");
}

// 分享文件
async function shareFile(name) {
  try {
    showMask("生成分享链接", "正在生成...");
    const res = await fetch(`/api/share?name=${encodeURIComponent(name)}`);
    const data = await res.json();
    hideMask();
    if (!data.success) throw new Error(data.error);
    prompt("分享链接（有效期内可直接访问）", data.shareUrl);
  } catch (err) {
    hideMask();
    alert("生成分享链接失败：" + err.message);
  }
}

// 删除文件
async function deleteFile(name) {
  if (!confirm(`确定要删除文件：${name}？删除后无法恢复！`)) return;
  try {
    showMask("删除文件", "正在删除...");
    const res = await fetch("/api/delete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name })
    });
    const data = await res.json();
    hideMask();
    if (!data.success) throw new Error(data.error);
    alert("删除成功");
    location.reload();
  } catch (err) {
    hideMask();
    alert("删除失败：" + err.message);
  }
}

// 拖拽上传
document.body.addEventListener("dragover", (e) => {
  e.preventDefault();
  e.stopPropagation();
});
document.body.addEventListener("drop", (e) => {
  e.preventDefault();
  e.stopPropagation();
  const files = Array.from(e.dataTransfer.files);
  if (files.length > 0) {
    document.getElementById("file-input").files = e.dataTransfer.files;
    const event = new Event("change");
    document.getElementById("file-input").dispatchEvent(event);
  }
});
</script>
</body>
</html>
  `, {
    headers: { "Content-Type": "text/html; charset=UTF-8" }
  });
}

// 工具函数
function formatSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(2) + " " + sizes[i];
}

function formatTime(dateStr) {
  return new Date(dateStr).toLocaleString("zh-CN");
}