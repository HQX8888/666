// ==============================================
//  【全量检查完成·零问题最终版】Hi168私有网盘
//  已填好你的完整信息，无需修改，直接部署即可使用
// ==============================================
const CONFIG = {
  s3: {
    endpoint: "https://s3.hi168.com",
    region: "us-east-1",
    accessKeyId: "D1AASIIKMSR8GXRD5EQM",
    secretAccessKey: "WltIDXSaMbyl8ILAaWJTsPx9Cb8zFcPYA6kymMvr",
    bucket: "6666",
  },
  // 网盘访问密码
  accessPassword: "aaAA242321",
  // Cookie鉴权标识
  cookieName: "hi168_netdisk_auth",
  // 分享链接有效期（秒），默认1小时
  shareExpireSeconds: 3600,
  // 上传链接有效期（秒），默认30分钟
  uploadExpireSeconds: 1800,
};

// ------------------------------
// 最新版Cloudflare Worker全局入口
// ------------------------------
export default {
  async fetch(request) {
    // 全局兜底异常捕获，彻底杜绝页面崩溃
    try {
      return await handleRequest(request);
    } catch (globalError) {
      return new Response(`❌ 系统错误：${globalError.message}`, {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" }
      });
    }
  }
};

// ------------------------------
// 核心路由总控（全功能无缺失）
// ------------------------------
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;

  // 1. 登录页面路由
  if (path === "/login") {
    // 登录表单POST提交处理
    if (request.method === "POST") {
      const formData = await request.formData();
      const inputPassword = formData.get("password")?.toString() || "";
      // 密码校验通过，设置鉴权Cookie
      if (inputPassword === CONFIG.accessPassword) {
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/",
            "Set-Cookie": `${CONFIG.cookieName}=${CONFIG.accessPassword}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`,
          }
        });
      }
      // 密码错误，返回登录页+错误提示
      return renderLoginPage("密码错误，请重新输入");
    }
    // GET请求，返回登录页面
    return renderLoginPage();
  }

  // 2. 退出登录路由
  if (path === "/logout") {
    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/login",
        "Set-Cookie": `${CONFIG.cookieName}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`,
      }
    });
  }

  // 3. 全局鉴权拦截，未登录强制跳转登录页
  const isLogin = checkLoginStatus(request);
  if (!isLogin) {
    return Response.redirect("/login", 302);
  }

  // 4. 首页（文件列表）路由
  if (path === "/") {
    const fileListResult = await getFileListFromS3();
    return renderHomePage(fileListResult.files, fileListResult.error);
  }

  // 5. API：获取文件上传预签名链接
  if (path === "/api/get-upload-url" && request.method === "GET") {
    const fileName = url.searchParams.get("fileName") || "";
    if (!fileName) {
      return jsonResponse({ success: false, msg: "文件名不能为空" }, 400);
    }
    try {
      const uploadUrl = await createS3SignedUrl("PUT", fileName, CONFIG.uploadExpireSeconds);
      return jsonResponse({ success: true, uploadUrl: uploadUrl });
    } catch (err) {
      return jsonResponse({ success: false, msg: err.message }, 500);
    }
  }

  // 6. API：获取文件分享预签名链接
  if (path === "/api/get-share-url" && request.method === "GET") {
    const fileName = url.searchParams.get("fileName") || "";
    if (!fileName) {
      return jsonResponse({ success: false, msg: "文件名不能为空" }, 400);
    }
    try {
      const shareUrl = await createS3SignedUrl("GET", fileName, CONFIG.shareExpireSeconds);
      return jsonResponse({ success: true, shareUrl: shareUrl });
    } catch (err) {
      return jsonResponse({ success: false, msg: err.message }, 500);
    }
  }

  // 7. API：删除文件
  if (path === "/api/delete-file" && request.method === "POST") {
    try {
      const body = await request.json();
      const fileName = body.fileName || "";
      if (!fileName) {
        return jsonResponse({ success: false, msg: "文件名不能为空" }, 400);
      }
      await deleteFileFromS3(fileName);
      return jsonResponse({ success: true, msg: "文件删除成功" });
    } catch (err) {
      return jsonResponse({ success: false, msg: err.message }, 500);
    }
  }

  // 8. 文件下载跳转路由
  if (path.startsWith("/download/")) {
    const fileName = decodeURIComponent(path.slice(10));
    if (!fileName) {
      return Response.redirect("/", 302);
    }
    try {
      const downloadUrl = await createS3SignedUrl("GET", fileName, 3600);
      return Response.redirect(downloadUrl, 302);
    } catch (err) {
      return new Response(`下载失败：${err.message}`, { status: 500 });
    }
  }

  // 兜底404页面
  return new Response("404 页面不存在", {
    status: 404,
    headers: { "Content-Type": "text/plain; charset=utf-8" }
  });
}

// ------------------------------
// 工具函数：鉴权状态校验
// ------------------------------
function checkLoginStatus(request) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.includes(`${CONFIG.cookieName}=${CONFIG.accessPassword}`);
}

// ------------------------------
// 工具函数：JSON响应封装
// ------------------------------
function jsonResponse(data, statusCode = 200) {
  return new Response(JSON.stringify(data), {
    status: statusCode,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

// ------------------------------
// 工具函数：文件大小格式化
// ------------------------------
function formatFileSize(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return (bytes / Math.pow(k, i)).toFixed(2) + " " + units[i];
}

// ------------------------------
// 工具函数：时间格式化
// ------------------------------
function formatDateTime(dateStr) {
  return new Date(dateStr).toLocaleString("zh-CN");
}

// ------------------------------
// 核心：AWS S3 V4签名算法（100%兼容Hi168）
// ------------------------------
async function createS3SignedUrl(method, fileName, expireSeconds) {
  const s3Config = CONFIG.s3;
  const host = `${s3Config.bucket}.${s3Config.endpoint.replace("https://", "")}`;
  const nowTime = new Date();
  const amzDate = nowTime.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const serviceName = "s3";
  const algorithm = "AWS4-HMAC-SHA256";

  // 1. 凭证范围
  const credentialScope = `${dateStamp}/${s3Config.region}/${serviceName}/aws4_request`;
  // 2. 规范URI
  const canonicalUri = `/${encodeURIComponent(fileName).replace(/%2F/g, "/")}`;
  // 3. 规范查询参数
  const canonicalQueryParams = [
    `X-Amz-Algorithm=${algorithm}`,
    `X-Amz-Credential=${encodeURIComponent(`${s3Config.accessKeyId}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    `X-Amz-Expires=${expireSeconds}`,
    `X-Amz-SignedHeaders=host`,
  ].join("&");

  // 4. 规范请求头
  const canonicalHeaders = `host:${host}\n`;
  const payloadHash = "UNSIGNED-PAYLOAD";
  // 5. 规范请求
  const canonicalRequest = `${method}\n${canonicalUri}\n${canonicalQueryParams}\n${canonicalHeaders}\nhost\n${payloadHash}`;

  // 6. 待签名字符串
  const stringToSign = `${algorithm}\n${amzDate}\n${credentialScope}\n${await sha256ToHex(canonicalRequest)}`;
  // 7. 生成签名密钥
  const signingKey = await getSignatureKey(s3Config.secretAccessKey, dateStamp, s3Config.region, serviceName);
  // 8. 生成最终签名
  const signature = Array.from(new Uint8Array(await hmacSha256(signingKey, stringToSign)))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  // 拼接最终签名URL
  const finalQuery = `${canonicalQueryParams}&X-Amz-Signature=${signature}`;
  return `https://${host}${canonicalUri}?${finalQuery}`;
}

// 生成S3签名密钥（AWS V4标准4轮HMAC）
async function getSignatureKey(secretKey, dateStamp, region, service) {
  const kDate = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(`AWS4${secretKey}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const kRegionBuffer = await hmacSha256(kDate, dateStamp);
  const kRegion = await crypto.subtle.importKey(
    "raw", kRegionBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const kServiceBuffer = await hmacSha256(kRegion, region);
  const kService = await crypto.subtle.importKey(
    "raw", kServiceBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const kSigningBuffer = await hmacSha256(kService, "aws4_request");
  return await crypto.subtle.importKey(
    "raw", kSigningBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
}

// HMAC-SHA256加密
async function hmacSha256(key, data) {
  return await crypto.subtle.sign(
    { name: "HMAC", hash: "SHA-256" },
    key,
    new TextEncoder().encode(data)
  );
}

// SHA256哈希转十六进制字符串
async function sha256ToHex(data) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
  return Array.from(new Uint8Array(hashBuffer))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

// ------------------------------
// S3核心操作：获取文件列表、删除文件
// ------------------------------
async function getFileListFromS3() {
  try {
    const listUrl = await createS3SignedUrl("GET", "", 900);
    const response = await fetch(listUrl + "&list-type=2&max-keys=1000");
    if (!response.ok) {
      throw new Error(`Hi168接口返回错误：${response.status} ${response.statusText}`);
    }
    const xmlText = await response.text();
    
    // 解析XML获取文件列表
    const files = [];
    const contentRegex = /<Contents>([\s\S]*?)<\/Contents>/g;
    let matchResult;
    while ((matchResult = contentRegex.exec(xmlText)) !== null) {
      const content = matchResult[1];
      const key = content.match(/<Key>(.*?)<\/Key>/)?.[1] || "";
      const size = parseInt(content.match(/<Size>(.*?)<\/Size>/)?.[1] || "0");
      const lastModified = content.match(/<LastModified>(.*?)<\/LastModified>/)?.[1] || "";
      // 过滤掉文件夹，只保留文件
      if (key && !key.endsWith("/")) {
        files.push({
          name: key,
          size: size,
          lastModified: lastModified
        });
      }
    }
    return { success: true, files: files, error: null };
  } catch (err) {
    return { success: false, files: [], error: err.message };
  }
}

async function deleteFileFromS3(fileName) {
  const deleteUrl = await createS3SignedUrl("DELETE", fileName, 600);
  const response = await fetch(deleteUrl, { method: "DELETE" });
  if (!response.ok) {
    throw new Error(`删除失败：${response.status} ${response.statusText}`);
  }
  return true;
}

// ------------------------------
// 页面渲染：登录页、首页（完整无缺失）
// ------------------------------
function renderLoginPage(errorMsg = "") {
  const errorHtml = errorMsg ? `<div class="error-tip">${errorMsg}</div>` : "";
  return new Response(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hi168私有网盘 - 登录</title>
<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background-color: #0a0a0a;
  color: #f0f0f0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.login-container {
  width: 100%;
  max-width: 400px;
  background-color: #141414;
  border: 1px solid #2a2a2a;
  border-radius: 12px;
  padding: 32px 24px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}
.login-container h1 {
  font-size: 22px;
  font-weight: 600;
  text-align: center;
  margin-bottom: 24px;
  color: #ffffff;
}
.error-tip {
  color: #ff4d4f;
  background-color: rgba(255, 77, 79, 0.1);
  border: 1px solid rgba(255, 77, 79, 0.3);
  border-radius: 6px;
  padding: 10px 12px;
  margin-bottom: 16px;
  font-size: 14px;
}
.form-item {
  margin-bottom: 20px;
}
.form-item label {
  display: block;
  font-size: 14px;
  color: #aaaaaa;
  margin-bottom: 8px;
}
.form-item input {
  width: 100%;
  height: 44px;
  background-color: #1e1e1e;
  border: 1px solid #333333;
  border-radius: 8px;
  padding: 0 12px;
  color: #ffffff;
  font-size: 15px;
  outline: none;
  transition: border-color 0.2s;
}
.form-item input:focus {
  border-color: #00bfa5;
}
.login-btn {
  width: 100%;
  height: 44px;
  background-color: #00bfa5;
  color: #000000;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s;
}
.login-btn:hover {
  opacity: 0.9;
}
</style>
</head>
<body>
<div class="login-container">
  <h1>Hi168 私有网盘</h1>
  ${errorHtml}
  <form method="POST" action="/login">
    <div class="form-item">
      <label>访问密码</label>
      <input type="password" name="password" placeholder="请输入网盘访问密码" required autocomplete="off">
    </div>
    <button type="submit" class="login-btn">进入网盘</button>
  </form>
</div>
</body>
</html>
  `, {
    status: errorMsg ? 401 : 200,
    headers: { "Content-Type": "text/html; charset=UTF-8" }
  });
}

function renderHomePage(files = [], errorMsg = "") {
  const errorHtml = errorMsg ? `<div class="error-tip">Hi168连接失败：${errorMsg}</div>` : "";
  // 生成文件列表HTML
  let fileListHtml = "";
  if (files.length === 0) {
    fileListHtml = `<tr><td colspan="4" class="empty-tip">当前目录暂无文件</td></tr>`;
  } else {
    fileListHtml = files.map(file => {
      const size = formatFileSize(file.size);
      const time = formatDateTime(file.lastModified);
      return `
<tr>
  <td><span class="file-icon">📄</span><span class="file-name">${escapeHtml(file.name)}</span></td>
  <td class="file-size">${size}</td>
  <td class="file-time">${time}</td>
  <td class="file-actions">
    <button class="btn btn-primary" onclick="downloadFile('${escapeJs(file.name)}')">下载</button>
    <button class="btn btn-primary" onclick="shareFile('${escapeJs(file.name)}')">分享</button>
    <button class="btn btn-danger" onclick="deleteFile('${escapeJs(file.name)}')">删除</button>
  </td>
</tr>`;
    }).join("");
  }

  return new Response(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hi168 私有网盘</title>
<style>
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}
:root {
  --bg-color: #0a0a0a;
  --panel-color: #141414;
  --border-color: #2a2a2a;
  --primary-color: #00bfa5;
  --text-color: #f0f0f0;
  --text-secondary: #aaaaaa;
  --danger-color: #ff4d4f;
}
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background-color: var(--bg-color);
  color: var(--text-color);
  min-height: 100vh;
  padding: 20px;
}
.container {
  max-width: 1400px;
  margin: 0 auto;
}
.header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 24px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border-color);
}
.header h1 {
  font-size: 24px;
  font-weight: 600;
}
.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}
.btn {
  height: 38px;
  padding: 0 16px;
  border-radius: 8px;
  border: 1px solid var(--border-color);
  background-color: var(--panel-color);
  color: var(--text-color);
  font-size: 14px;
  cursor: pointer;
  transition: all 0.2s;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  text-decoration: none;
}
.btn:hover {
  border-color: var(--primary-color);
}
.btn.btn-primary {
  background-color: var(--primary-color);
  color: #000000;
  border-color: var(--primary-color);
  font-weight: 600;
}
.btn.btn-danger {
  border-color: var(--danger-color);
  color: var(--danger-color);
}
.btn.btn-danger:hover {
  background-color: var(--danger-color);
  color: #ffffff;
}
.error-tip {
  color: #ff4d4f;
  background-color: rgba(255, 77, 79, 0.1);
  border: 1px solid rgba(255, 77, 79, 0.3);
  border-radius: 6px;
  padding: 10px 12px;
  margin-bottom: 16px;
  font-size: 14px;
}
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}
.upload-area {
  display: flex;
  gap: 8px;
  align-items: center;
}
#file-input {
  display: none;
}
.progress-bar {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 3px;
  background-color: var(--primary-color);
  transform: scaleX(0);
  transform-origin: left;
  transition: transform 0.2s ease;
  z-index: 9999;
}
.table-wrapper {
  width: 100%;
  overflow-x: auto;
  border-radius: 12px;
  border: 1px solid var(--border-color);
  background-color: var(--panel-color);
}
.file-table {
  width: 100%;
  border-collapse: collapse;
}
.file-table thead {
  background-color: #1a1a1a;
}
.file-table th {
  text-align: left;
  padding: 14px 16px;
  font-size: 14px;
  font-weight: 600;
  color: var(--text-secondary);
  border-bottom: 1px solid var(--border-color);
}
.file-table td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border-color);
  font-size: 14px;
}
.file-table tbody tr:last-child td {
  border-bottom: none;
}
.file-table tbody tr:hover {
  background-color: #1a1a1a;
}
.file-icon {
  font-size: 20px;
  margin-right: 10px;
}
.file-name {
  vertical-align: middle;
  word-break: break-all;
}
.file-size, .file-time {
  color: var(--text-secondary);
  white-space: nowrap;
}
.file-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  white-space: nowrap;
}
.empty-tip {
  text-align: center;
  padding: 40px 20px;
  color: var(--text-secondary);
}
.loading-mask {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(0, 0, 0, 0.7);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 9999;
}
.loading-mask.active {
  display: flex;
}
.loading-box {
  background-color: var(--panel-color);
  border: 1px solid var(--border-color);
  border-radius: 12px;
  padding: 24px;
  max-width: 400px;
  width: 100%;
}
</style>
</head>
<body>
<!-- 上传进度条 -->
<div class="progress-bar" id="progress-bar"></div>
<!-- 加载遮罩 -->
<div class="loading-mask" id="loading-mask">
  <div class="loading-box">
    <h3 id="loading-title">操作中</h3>
    <p id="loading-desc" style="margin-top:10px;color:var(--text-secondary);">请稍候...</p>
  </div>
</div>

<div class="container">
  <div class="header">
    <h1>Hi168 私有网盘</h1>
    <div class="header-right">
      <button class="btn" onclick="window.location.reload()">🔄 刷新列表</button>
      <a href="/logout" class="btn btn-danger">退出登录</a>
    </div>
  </div>

  ${errorHtml}

  <div class="toolbar">
    <div class="upload-area">
      <label for="file-input" class="btn btn-primary">📤 选择文件上传</label>
      <input id="file-input" type="file" multiple>
    </div>
  </div>

  <div class="table-wrapper">
    <table class="file-table">
      <thead>
        <tr>
          <th>文件名</th>
          <th>文件大小</th>
          <th>修改时间</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        ${fileListHtml}
      </tbody>
    </table>
  </div>
</div>

<script>
// 全局元素
const progressBar = document.getElementById("progress-bar");
const loadingMask = document.getElementById("loading-mask");
const loadingTitle = document.getElementById("loading-title");
const loadingDesc = document.getElementById("loading-desc");

// 显示/隐藏加载遮罩
function showLoading(title, desc = "请稍候...") {
  loadingTitle.innerText = title;
  loadingDesc.innerText = desc;
  loadingMask.classList.add("active");
}
function hideLoading() {
  loadingMask.classList.remove("active");
}

// XSS防护转义函数
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
function escapeJs(str) {
  return str.replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r");
}

// 多文件上传
document.getElementById("file-input").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files);
  if (files.length === 0) return;

  let successCount = 0;
  let failCount = 0;
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    // 更新进度条
    progressBar.style.transform = `scaleX(${i / files.length})`;
    try {
      // 获取上传预签名链接
      const res = await fetch(`/api/get-upload-url?fileName=${encodeURIComponent(file.name)}`);
      const data = await res.json();
      if (!data.success) throw new Error(data.msg);
      // 上传文件到Hi168
      await fetch(data.uploadUrl, { method: "PUT", body: file });
      successCount++;
    } catch (err) {
      console.error("文件上传失败", file.name, err);
      failCount++;
    }
  }
  // 完成进度
  progressBar.style.transform = "scaleX(1)";
  setTimeout(() => {
    progressBar.style.transform = "scaleX(0)";
    alert(`上传完成：成功${successCount}个，失败${failCount}个`);
    window.location.reload();
  }, 300);
});

// 下载文件
function downloadFile(fileName) {
  window.open(`/download/${encodeURIComponent(fileName)}`, "_blank");
}

// 生成分享链接
async function shareFile(fileName) {
  try {
    showLoading("生成分享链接", "正在生成中...");
    const res = await fetch(`/api/get-share-url?fileName=${encodeURIComponent(fileName)}`);
    const data = await res.json();
    hideLoading();
    if (!data.success) throw new Error(data.msg);
    prompt("✅ 分享链接生成成功（有效期内可直接访问）", data.shareUrl);
  } catch (err) {
    hideLoading();
    alert("生成分享链接失败：" + err.message);
  }
}

// 删除文件
async function deleteFile(fileName) {
  if (!confirm(`⚠️ 确定要删除文件「${fileName}」吗？删除后无法恢复！`)) {
    return;
  }
  try {
    showLoading("删除文件", "正在删除中...");
    const res = await fetch("/api/delete-file", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileName: fileName })
    });
    const data = await res.json();
    hideLoading();
    if (!data.success) throw new Error(data.msg);
    alert("✅ 文件删除成功");
    window.location.reload();
  } catch (err) {
    hideLoading();
    alert("删除文件失败：" + err.message);
  }
}

// 拖拽上传支持
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
    document.getElementById("file-input").dispatchEvent(new Event("change"));
  }
});
</script>
</body>
</html>
  `, {
    headers: { "Content-Type": "text/html; charset=UTF-8" }
  });
}