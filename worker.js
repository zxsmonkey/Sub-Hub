// 通用的路径验证和节点名称提取函数
function validateSubscriptionPath(path) {
  return /^[a-z0-9-]{5,50}$/.test(path);
}

// 节点类型常量定义
const NODE_TYPES = {
  SS: 'ss://',
  VMESS: 'vmess://',
  TROJAN: 'trojan://',
  VLESS: 'vless://',
  SOCKS: 'socks://',
  HYSTERIA2: 'hysteria2://',
  TUIC: 'tuic://',
  SNELL: 'snell,'
};

function extractNodeName(nodeLink) {
  if (!nodeLink) return '未命名节点';
  
  // 处理snell节点
  if(nodeLink.includes(NODE_TYPES.SNELL)) {
    const name = nodeLink.split('=')[0].trim();
    return name || '未命名节点';
  }
  
  // 处理 VMess 链接
  if (nodeLink.toLowerCase().startsWith(NODE_TYPES.VMESS)) {
    try {
      const config = JSON.parse(safeBase64Decode(nodeLink.substring(8)));
      if (config.ps) {
        return safeUtf8Decode(config.ps);
      }
    } catch {}
    return '未命名节点';
  }

  // 处理其他使用哈希标记名称的链接类型（SS、TROJAN、VLESS、SOCKS、Hysteria2、TUIC等）
  const hashIndex = nodeLink.indexOf('#');
  if (hashIndex !== -1) {
    try {
      return decodeURIComponent(nodeLink.substring(hashIndex + 1));
    } catch {
      return nodeLink.substring(hashIndex + 1) || '未命名节点';
    }
  }
  return '未命名节点';
}

export default {
  async fetch(request, env) {
    // 解析请求路径和参数
    const url = new URL(request.url);
    const pathname = url.pathname;
    const method = request.method;

    // 检查是否有查询参数
    if (url.search && !pathname.startsWith('/admin')) {
      return new Response('Not Found', { status: 404 });
    }

    // 从环境变量获取配置路径，如果未设置则使用默认值
    const adminPath = env.ADMIN_PATH || 'admin';
    
    // 从环境变量获取登录凭据
    const adminUsername = env.ADMIN_USERNAME || 'admin';
    const adminPassword = env.ADMIN_PASSWORD || 'password';
    
    // 处理登录页面请求
    if (pathname === `/${adminPath}/login`) {
      if (method === "GET") {
        return serveLoginPage(adminPath);
      } else if (method === "POST") {
        return handleLogin(request, env, adminUsername, adminPassword, adminPath);
      }
    }
    
    // 处理登出请求
    if (pathname === `/${adminPath}/logout`) {
      return handleLogout(request, env, adminPath);
    }
    
    // 处理管理面板请求
    if (pathname === `/${adminPath}`) {
      const isAuthenticated = await verifySession(request, env);
      if (!isAuthenticated) {
        return Response.redirect(`${url.origin}/${adminPath}/login`, 302);
      }
      return serveAdminPanel(env, adminPath);
    }
    
    // 处理API请求
    if (pathname.startsWith(`/${adminPath}/api/`)) {
      // 验证会话
      const isAuthenticated = await verifySession(request, env);
      if (!isAuthenticated) {
        return new Response(JSON.stringify({
          success: false,
          message: '未授权访问'
        }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      // 处理节点管理API请求
      const nodeApiMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)/nodes(?:/([^/]+|reorder))?$`));
      if (nodeApiMatch) {
        const subscriptionPath = nodeApiMatch[1];
        const nodeId = nodeApiMatch[2];
        
        try {
          // 更新节点顺序
          if (nodeId === 'reorder' && method === 'POST') {
            const { orders } = await request.json();
            
            if (!Array.isArray(orders) || orders.length === 0) {
              return new Response(JSON.stringify({
                success: false,
                message: '无效的排序数据'
              }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            
            // 获取订阅ID
            const { results: subResults } = await env.DB.prepare(
              "SELECT id FROM subscriptions WHERE path = ?"
            ).bind(subscriptionPath).all();
            
            if (!subResults?.length) {
              return new Response(JSON.stringify({
                success: false,
                message: '订阅不存在'
              }), {
                status: 404,
                headers: { 'Content-Type': 'application/json' }
              });
            }
            
            const subscriptionId = subResults[0].id;
            
            // 使用事务来确保数据一致性
            const statements = [];
            
            // 准备更新语句
            for (const { id, order } of orders) {
              statements.push(env.DB.prepare(
                "UPDATE nodes SET node_order = ? WHERE id = ? AND subscription_id = ?"
                              ).bind(order, id, subscriptionId));
            }
            
            // 执行批量更新
            const result = await env.DB.batch(statements);
            
            return new Response(JSON.stringify({
              success: true,
              message: '节点顺序已更新'
            }), {
              headers: { 'Content-Type': 'application/json' }
            });
          }
          
          // 获取节点列表
          if (!nodeId && method === 'GET') {
            return handleGetNodes(env, subscriptionPath);
          }
          
          // 创建新节点
          if (!nodeId && method === 'POST') {
            return handleCreateNode(request, env, subscriptionPath);
          }
          
          // 更新节点
          if (nodeId && nodeId !== 'reorder' && method === 'PUT') {
            return handleUpdateNode(request, env, subscriptionPath, nodeId);
          }
          
          // 删除节点
          if (nodeId && nodeId !== 'reorder' && method === 'DELETE') {
            return handleDeleteNode(env, subscriptionPath, nodeId);
          }
          
          // 切换节点状态
          if (nodeId && nodeId !== 'reorder' && method === 'PATCH') {
            return handleToggleNode(env, subscriptionPath, nodeId, request);
          }
          
          return new Response(JSON.stringify({
            success: false,
            message: 'Method Not Allowed'
          }), {
            status: 405,
            headers: { 'Content-Type': 'application/json' }
          });
          
        } catch (error) {
          console.error('API请求处理失败:', error);
          return new Response(JSON.stringify({
            success: false,
            message: error.message || '服务器内部错误'
          }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      }
      
      // 处理订阅管理API请求
      if (pathname.startsWith(`/${adminPath}/api/subscriptions`)) {
        // 获取单个订阅内容
        const getOneMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
        if (getOneMatch && method === 'GET') {
          return handleGetSubscription(env, getOneMatch[1]);
      }
      
      // 获取订阅列表
      if (pathname === `/${adminPath}/api/subscriptions` && method === 'GET') {
        return handleGetSubscriptions(env);
      }
      
      // 创建新订阅
      if (pathname === `/${adminPath}/api/subscriptions` && method === 'POST') {
          try {
            const { name, path } = await request.json();
            
            if (!name || !validateSubscriptionPath(path)) {
              return createErrorResponse('无效的参数', 400);
            }
            
            // 检查路径是否已存在
            const { results } = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM subscriptions WHERE path = ?"
            ).bind(path).all();
            
            if (results[0].count > 0) {
              return createErrorResponse('该路径已被使用', 400);
            }
            
            // 创建订阅
            const result = await env.DB.prepare(
              "INSERT INTO subscriptions (name, path) VALUES (?, ?)"
                          ).bind(name, path).run();

            if (!result.success) {
              throw new Error('创建订阅失败');
            }

            return createSuccessResponse(null, '订阅创建成功');
          } catch (error) {
            console.error('创建订阅失败:', error);
            return createErrorResponse('创建订阅失败: ' + error.message);
          }
        }
        
        // 更新订阅信息
      const updateMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
      if (updateMatch && method === 'PUT') {
          const data = await request.json();
          return handleUpdateSubscriptionInfo(env, updateMatch[1], data);
      }
      
      // 删除订阅
      const deleteMatch = pathname.match(new RegExp(`^/${adminPath}/api/subscriptions/([^/]+)$`));
      if (deleteMatch && method === 'DELETE') {
        return handleDeleteSubscription(env, deleteMatch[1]);
      }

        return new Response(JSON.stringify({
          success: false,
          message: 'Method Not Allowed'
        }), {
          status: 405,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return new Response(JSON.stringify({
        success: false,
        message: 'Not Found'
      }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // 处理订阅请求
    if (pathname.startsWith('/')) {
      // 检查路径格式是否合法（只允许一级或两级路径，如 /path 或 /path/surge 或 /path/v2ray 或 /path/clash）
      const pathParts = pathname.split('/').filter(Boolean);
      if (pathParts.length > 2) {
        return new Response('Not Found', { status: 404 });
      }
      
      if (pathParts.length === 2 && !['surge', 'v2ray', 'clash'].includes(pathParts[1])) {
        return new Response('Not Found', { status: 404 });
      }

      try {
        // 获取基本路径
        let basePath = pathname;
        if (pathname.endsWith('/surge')) {
          basePath = pathname.slice(1, -6);  // 移除开头的/和结尾的/surge
        } else if (pathname.endsWith('/v2ray')) {
          basePath = pathname.slice(1, -6);  // 移除开头的/和结尾的/v2ray
        } else if (pathname.endsWith('/clash')) {
          basePath = pathname.slice(1, -6);  // 移除开头的/和结尾的/clash
        } else {
          basePath = pathname.slice(1);      // 只移除开头的/
        }
        
        // 获取订阅信息
        const { results } = await env.DB.prepare(
          "SELECT * FROM subscriptions WHERE path = ?"
        ).bind(basePath).all();
        
        const subscription = results[0];
        
        if (subscription) {
          // 生成订阅内容
          const content = await generateSubscriptionContent(env, basePath);
          
          // 根据请求路径返回不同格式的内容
          if (pathname.endsWith('/surge')) {
            // 返回 Surge 格式
            const surgeContent = convertToSurge(content);
            return new Response(surgeContent, {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          } else if (pathname.endsWith('/v2ray')) {
            // 返回 Base64 编码格式，排除 snell 节点，包括 VLESS 节点
            const filteredContent = filterSnellNodes(content);
            const base64Content = safeBase64Encode(filteredContent);
            
            return new Response(base64Content, {
              headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
          } else if (pathname.endsWith('/clash')) {
            // 返回 Clash 格式
            const clashContent = convertToClash(content);
            return new Response(clashContent, {
              headers: { 'Content-Type': 'text/yaml; charset=utf-8' },
            });
          }
          
          // 返回普通订阅内容，排除 snell 节点
          const filteredContent = filterSnellNodes(content);
          return new Response(filteredContent, {
            headers: { 'Content-Type': 'text/plain; charset=utf-8' },
          });
        }
      } catch (error) {
        console.error('处理订阅请求失败:', error);
        return new Response('Internal Server Error', { status: 500 });
      }
      
      // 如果没有找到匹配的订阅，返回404
      return new Response('Not Found', { status: 404 });
    }
    
    // 其他所有路径返回 404
    return new Response('Not Found', { status: 404 });
  },
};

// 添加获取单个订阅的处理函数
async function handleGetSubscription(env, path) {
  try {
    const { results } = await env.DB.prepare(
      "SELECT * FROM subscriptions WHERE path = ?"
    ).bind(path).all();
    
    if (!results || results.length === 0) {
      return createErrorResponse('订阅不存在', 404);
    }
    
    return createSuccessResponse(results[0]);
  } catch (error) {
    console.error('获取订阅内容失败:', error);
    return createErrorResponse('获取订阅内容失败: ' + error.message);
  }
}

// 提供登录页面HTML
function serveLoginPage(adminPath) {
  const html = `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sub-Hub - 登录</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.0.0/css/all.min.css">
    <style>
      :root {
        --primary-color: #4e73df;
        --success-color: #1cc88a;
        --danger-color: #e74a3b;
        --transition-timing: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        --box-shadow-light: 0 2px 10px rgba(0,0,0,0.05);
        --box-shadow-medium: 0 4px 15px rgba(0,0,0,0.08);
        --font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
        --text-color: #2d3748;
        --text-color-secondary: #444;
        --border-radius-sm: 8px;
        --border-radius-md: 12px;
        --border-radius-lg: 16px;
      }
      
      * {
        transition: all var(--transition-timing);
        font-family: var(--font-family);
      }
      
      html {
        scrollbar-gutter: stable;
      }
      
      
      /* 防止模态框打开时页面偏移 */
      .modal-open {
        padding-right: 0 !important;
      }

      /* 修复模态框背景遮罩的宽度 */
      .modal-backdrop {
        width: 100vw !important;
      }

      /* 优化模态框布局 */
      .modal-dialog {
        margin-right: auto !important;
        margin-left: auto !important;
        padding-right: 0 !important;
      }

      /* 标题和重要文字样式 */
      .navbar-brand,
      .subscription-name,
      .modal-title,
      .form-label {
        font-weight: 600;
        color: var(--text-color);
      }

      /* 按钮统一样式 */
      .btn,
      .logout-btn {
        font-weight: 500;
      }

      /* 次要文字样式 */
      .link-label,
      .form-text {
        color: var(--text-color-secondary);
      }

      /* 链接标签文字加粗 */
      .link-label small > span > span {
        font-weight: 600;
      }
      
      body {
        font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
      }
      
      .login-container {
        background-color: #fff;
        border-radius: 16px;
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        overflow: hidden;
        width: 360px;
        max-width: 90%;
      }
      
      .login-header {
        background: linear-gradient(120deg, var(--primary-color), #224abe);
        padding: 2rem 1.5rem;
        text-align: center;
        color: white;
      }
      
      .login-icon {
        background-color: white;
        color: var(--primary-color);
        width: 80px;
        height: 80px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 1rem;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
      }
      
      .login-icon i {
        font-size: 2.5rem;
      }
      
      .login-title {
        font-weight: 600;
        margin-bottom: 0.5rem;
      }
      
      .login-subtitle {
        opacity: 0.8;
        font-size: 0.9rem;
      }
      
      .login-form {
        padding: 2rem;
      }
      
      .form-floating {
        margin-bottom: 1.5rem;
      }
      
      .form-floating input {
        border-radius: 8px;
        height: 56px;
        border: 2px solid #e7eaf0;
        box-shadow: none;
      }
      
      .form-floating input:focus {
        border-color: var(--primary-color);
        box-shadow: 0 0 0 0.25rem rgba(78, 115, 223, 0.15);
      }
      
      .form-floating label {
        color: #7e7e7e;
        padding-left: 1rem;
      }
      
      .btn-login {
        background: linear-gradient(120deg, var(--primary-color), #224abe);
        border: none;
        border-radius: 8px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        width: 100%;
        margin-top: 1rem;
        box-shadow: 0 4px 10px rgba(78, 115, 223, 0.35);
        transition: all 0.2s ease;
      }
      
      .btn-login:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 15px rgba(78, 115, 223, 0.4);
      }
      
      .alert {
        border-radius: 8px;
        font-size: 0.9rem;
        margin-bottom: 1.5rem;
        display: none;
      }

    </style>
  </head>
  <body>
    <div class="login-container">
      <div class="login-header">
        <div class="login-icon">
          <i class="fas fa-cube"></i>
        </div>
        <h3 class="login-title">Sub-Hub</h3>
        <p class="login-subtitle">请登录以继续使用</p>
      </div>
      
      <div class="login-form">
        <div class="alert alert-danger" id="loginAlert" role="alert">
          <i class="fas fa-exclamation-triangle me-2"></i>
          <span id="alertMessage">用户名或密码错误</span>
        </div>
        
        <form id="loginForm">
          <div class="form-floating">
            <input type="text" class="form-control" id="username" name="username" placeholder="用户名" required>
            <label for="username"><i class="fas fa-user me-2"></i>用户名</label>
          </div>
          
          <div class="form-floating">
            <input type="password" class="form-control" id="password" name="password" placeholder="密码" required>
            <label for="password"><i class="fas fa-lock me-2"></i>密码</label>
          </div>
          
          <button type="submit" class="btn btn-primary btn-login">
            <i class="fas fa-sign-in-alt me-2"></i>登录
          </button>
        </form>
      </div>
    </div>
    
    <script>
      document.getElementById('loginForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
          const response = await fetch('/${adminPath}/login', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
          });
          
          const data = await response.json();
          
          if (data.success) {
            // 登录成功，重定向到管理面板
            window.location.href = data.redirect;
          } else {
            // 显示错误消息
            document.getElementById('alertMessage').textContent = data.message;
            document.getElementById('loginAlert').style.display = 'block';
          }
        } catch (error) {
          // 显示错误消息
          document.getElementById('alertMessage').textContent = '登录请求失败，请重试';
          document.getElementById('loginAlert').style.display = 'block';
        }
      });
    </script>
  </body>
  </html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// 验证会话
async function verifySession(request, env) {
  const sessionId = getSessionFromCookie(request);
  if (!sessionId) return false;
  
  const now = Date.now();
  const { results } = await env.DB.prepare(`
    UPDATE sessions 
    SET expires_at = ? 
    WHERE session_id = ? AND expires_at > ?
    RETURNING *
  `).bind(now + 24 * 60 * 60 * 1000, sessionId, now).all();
  
  return results.length > 0;
}

// 从Cookie中获取会话ID
function getSessionFromCookie(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const sessionCookie = cookieHeader.split(';')
    .find(cookie => cookie.trim().startsWith('session='));
  return sessionCookie ? sessionCookie.trim().substring(8) : null;
}

// 生成安全的会话令牌
async function generateSecureSessionToken(username, env) {
  // 清理过期会话和用户旧会话
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now),
    env.DB.prepare("DELETE FROM sessions WHERE username = ?").bind(username)
  ]);

  const sessionId = crypto.randomUUID();
  const expiresAt = now + 24 * 60 * 60 * 1000; // 24小时后过期
  
  await env.DB.prepare(`
    INSERT INTO sessions (session_id, username, expires_at) 
    VALUES (?, ?, ?)
  `).bind(sessionId, username, expiresAt).run();

  return sessionId;
}

// 处理登录请求
async function handleLogin(request, env, adminUsername, adminPassword, adminPath) {
  const { username, password } = await request.json();
  
  if (!username || !password || username !== adminUsername || password !== adminPassword) {
    return new Response(JSON.stringify({
      success: false,
      message: '用户名或密码错误'
    }), {
      headers: { 'Content-Type': 'application/json' },
      status: 401
    });
  }

  const sessionId = await generateSecureSessionToken(username, env);
  const headers = new Headers({
    'Content-Type': 'application/json',
    'Set-Cookie': `session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400; Secure`
  });
  
  return new Response(JSON.stringify({
    success: true,
    message: '登录成功',
    redirect: `/${adminPath}`
  }), { headers });
}

// 处理登出请求
async function handleLogout(request, env, adminPath) {
  const sessionId = getSessionFromCookie(request);
  if (sessionId) {
    await env.DB.prepare("DELETE FROM sessions WHERE session_id = ?").bind(sessionId).run();
  }
  
  const headers = new Headers({
    'Set-Cookie': `session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure`
  });
  
  return Response.redirect(`${new URL(request.url).origin}/${adminPath}/login`, 302);
}

// 修改管理面板HTML生成函数
function serveAdminPanel(env, adminPath) {
  const html = `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sub-Hub</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.0.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js"></script>
    <style>
      :root {
        --primary-color: #4e73df;
        --success-color: #1cc88a;
        --danger-color: #e74a3b;
        --transition-timing: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        --box-shadow-light: 0 2px 10px rgba(0,0,0,0.05);
        --box-shadow-medium: 0 4px 15px rgba(0,0,0,0.08);
        --font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
        --text-color: #2d3748;
        --text-color-secondary: #444;
        --border-radius-sm: 8px;
        --border-radius-md: 12px;
        --border-radius-lg: 16px;
      }
      
      * {
        transition: all var(--transition-timing);
        font-family: var(--font-family);
      }
      
      html {
        scrollbar-gutter: stable;
      }
      
            body {        font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;        background-color: #f8f9fc;        padding: 20px 0;        overflow-y: scroll;      }      /* 防止模态框打开时页面偏移 */      .modal-open {        padding-right: 0 !important;      }      /* 修复模态框背景遮罩的宽度 */      .modal-backdrop {        width: 100vw !important;      }      /* 优化模态框布局 */      .modal-dialog {        margin-right: auto !important;        margin-left: auto !important;        padding-right: 0 !important;      }      /* 标题和重要文字样式 */      .navbar-brand,      .subscription-name,      .modal-title,      .form-label {        font-weight: 600;        color: var(--text-color);      }      /* 按钮统一样式 */      .btn,      .logout-btn {        font-weight: 500;      }      /* 次要文字样式 */      .subscription-meta,      .link-label,      .form-text {        color: var(--text-color-secondary);      }      /* 链接标签文字加粗 */      .link-label small > span > span {        font-weight: 600;      }
      
            .navbar {        background-color: white;        box-shadow: var(--box-shadow-light);        padding: 1rem 1.5rem;        margin-bottom: 0.5rem;        height: 80px;        display: flex;        align-items: center;        transform: translateY(0);      }            .navbar:hover {        box-shadow: var(--box-shadow-medium);      }            .navbar-brand {        font-weight: bold;        color: #000;        display: flex;        align-items: center;        font-size: 1.8rem;      }            .navbar-brand i {        font-size: 2.2rem;        margin-right: 0.8rem;        color: #000;      }            .navbar-user {        display: flex;        align-items: center;      }            .navbar-user .user-name {        font-weight: 500;      }            .logout-btn {        color: #4a4a4a;        background: none;        border: none;        margin-left: 1rem;        padding: 0.375rem 0.75rem;        border-radius: 0.25rem;        text-decoration: none;        font-weight: 500;      }            .logout-btn:hover {        background-color: #f8f9fa;        color: var(--danger-color);        text-decoration: none;      }            .logout-btn:focus {        text-decoration: none;        outline: none;      }            .container {        max-width: 1100px;      }
      
      textarea {
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        resize: vertical;
        min-height: 300px;
        max-height: 800px;
        height: 300px;
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 0.9rem;
        line-height: 1.5;
        padding: 12px;
      }
      
      .link-label {
        display: flex;
        flex-direction: column;
        margin-top: 1rem;
        color: #444;
        font-size: 0.9rem;
      }

      .link-label small {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
      }

      .link-label small > span {
        display: flex;
        align-items: center;
        gap: 0.25rem;
        font-size: 0.9rem;
      }

      .link-label small > span > span {
        display: inline-block;
        width: 90px;
        color: var(--text-color);
        font-weight: 600;
        text-align: justify;
        text-align-last: justify;
        font-size: 0.9rem;
      }

      .link-label a {
        margin-left: 0;
        color: var(--primary-color);
        text-decoration: none;
        word-break: break-all;
        font-weight: 700;
        font-size: 0.9rem;
      }
      
      .link-label .link:hover {
        text-decoration: underline;
      }
      
      .btn-group {
        display: flex;
        gap: 0.5rem;
        margin-top: 1rem;
      }
      
      .toast-container {
        position: fixed;
        top: 1rem;
        right: 1rem;
        z-index: 1050;
      }
      
      @media (max-width: 767px) {
        .btn-group {
          flex-direction: column;
        }
      }
      
      .subscription-list {
        margin-bottom: 2rem;
      }
      
      .subscription-item {
        background: #fff;
        border-radius: var(--border-radius-md);
        padding: 1.5rem;
        margin-bottom: 1.5rem;
        box-shadow: var(--box-shadow-light);
        border: 1px solid #eaeaea;
        overflow: hidden;
        transition: margin-bottom 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
      }

      .edit-button {
        position: absolute;
        top: 1rem;
        right: 1rem;
        z-index: 1;
      }

      .edit-button .btn {
        padding: 0.25rem 0.5rem;
        font-size: 0.875rem;
      }

      .subscription-item:hover {
        box-shadow: var(--box-shadow-medium);
      }

      .subscription-edit-area {
        max-height: 0;
        overflow: hidden;
        opacity: 0;
        transform: translateY(-10px);
        padding: 0;
        margin: 0;
        will-change: max-height, opacity, transform, padding, margin;
      }

      .subscription-edit-area.active {
        max-height: 300px;
        opacity: 1;
        transform: translateY(0);
        padding: 1rem;
        margin-top: 0.5rem;
      }

      .subscription-edit-area textarea {
        width: 100%;
        height: 200px;
        min-height: 200px;
        max-height: 200px;
        margin-bottom: 1rem;
        padding: 1rem;
        border: 1px solid #e5e7eb;
        border-radius: var(--border-radius-sm);
        font-size: 0.9rem;
        line-height: 1.5;
        resize: none;
        box-shadow: var(--box-shadow-light);
        opacity: 0;
        transform: translateY(5px);
      }

      .subscription-edit-area.active textarea {
        opacity: 1;
        transform: translateY(0);
      }

      .subscription-edit-actions {
        display: flex;
        gap: 0.5rem;
        justify-content: flex-end;
        opacity: 0;
        transform: translateY(5px);
      }

      .subscription-edit-area.active .subscription-edit-actions {
        opacity: 1;
        transform: translateY(0);
        transition-delay: 0.05s;
      }

      .toast {
        transform: translateY(0);
      }

      .toast.hide {
        transform: translateY(-100%);
      }

      @keyframes fadeIn {
        from {
          opacity: 0;
          transform: translateY(10px);
        }
        to {
          opacity: 1;
          transform: translateY(0);
        }
      }

      .subscription-item {
        animation: fadeIn 0.5s ease-out;
      }

      .path-error {
        color: #dc3545;
        font-size: 0.875em;
        margin-top: 0.25rem;
        display: none;
      }

      .form-control.is-invalid {
        border-color: #dc3545;
        padding-right: calc(1.5em + 0.75rem);
        background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' width='12' height='12' fill='none' stroke='%23dc3545'%3e%3ccircle cx='6' cy='6' r='4.5'/%3e%3cpath stroke-linejoin='round' d='M5.8 3.6h.4L6 6.5z'/%3e%3ccircle cx='6' cy='8.2' r='.6' fill='%23dc3545' stroke='none'/%3e%3c/svg%3e");
        background-repeat: no-repeat;
        background-position: right calc(0.375em + 0.1875rem) center;
        background-size: calc(0.75em + 0.375rem) calc(0.75em + 0.375rem);
      }

      .form-control.is-valid {
        border-color: #198754;
        padding-right: calc(1.5em + 0.75rem);
        background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 8 8'%3e%3cpath fill='%23198754' d='M2.3 6.73L.6 4.53c-.4-1.04.46-1.4 1.1-.8l1.1 1.4 3.4-3.8c.6-.63 1.6-.27 1.2.7l-4 4.6c-.43.5-.8.4-1.1.1z'/%3e%3c/svg%3e");
        background-repeat: no-repeat;
        background-position: right calc(0.375em + 0.1875rem) center;
        background-size: calc(0.75em + 0.375rem) calc(0.75em + 0.375rem);
      }

      .subscription-name {
        font-size: 1.5rem;
        font-weight: 600;
        color: #2d3748;
        margin-bottom: 0.75rem;
        line-height: 1.2;
      }

      .node-count {
        display: inline-flex;
        align-items: center;
        color: var(--text-color-secondary);
        font-size: 1rem;
        margin-left: 0.75rem;
      }

      .node-count i {
        margin-right: 0.35rem;
        font-size: 1rem;
      }

      

      .subscription-actions {
        margin-top: 1.25rem;
        padding-top: 0.75rem;
        display: flex;
        flex-direction: column;
        gap: 0.5rem;
      }

      .subscription-actions .btn {
        width: 100%;
        padding: 0.5rem 1.25rem;
        font-weight: 500;
        border-radius: 8px;
        font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif;
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .subscription-actions .btn i {
        margin-right: 0.5rem;
      }

      /* 操作按钮样式 */
      .node-actions {
        display: flex !important;
        flex-direction: row !important;
        flex-wrap: nowrap !important;
        gap: 4px;
        flex-shrink: 0;
      }

      .node-actions .btn {
        padding: 4px 8px !important;
        min-width: 32px !important;
        height: 28px !important;
        display: inline-flex !important;
        align-items: center;
        justify-content: center;
        margin: 0 !important;
      }

      .node-actions .btn i {
        font-size: 14px;
        line-height: 1;
        margin: 0 !important;
      }

      .node-checkbox {
        vertical-align: top;
        margin: 0;
        margin-top: 1.5px;
      }

            /* 移动端适配样式 */      @media (max-width: 767px) {        /* 基础布局调整 */        .container {          padding: 0 15px;        }        .navbar {          margin-bottom: 2rem;          padding: 0.8rem 1rem;        }        .btn-group {          flex-direction: column;        }        /* 订阅项样式调整 */        .subscription-item {          padding: 1rem;        }        .subscription-item > div {          flex-direction: column;          align-items: flex-start !important;        }        .subscription-item .link-label {          margin: 1rem 0 0;          width: 100%;        }        .subscription-actions {          margin-top: 1rem;          width: 100%;          flex-direction: row !important;          gap: 0.5rem;        }        .subscription-actions .btn {          flex: 1;          font-size: 0.875rem;          padding: 0.5rem;        }        .subscription-actions .btn i {          margin-right: 0.25rem;          font-size: 0.875rem;        }        /* 模态框调整 */        .modal-dialog {          margin: 0.5rem;        }        .modal-content {          border-radius: 1rem;        }        /* Toast提示调整 */        .toast-container {          right: 0;          left: 0;          bottom: 1rem;          top: auto;          margin: 0 1rem;        }        .toast {          width: 100%;        }        /* 节点列表移动端优化 */        .table {          table-layout: fixed;          width: 100%;          margin-bottom: 0 !important;        }        .table thead th:first-child {          padding-left: 1rem !important;          width: 100% !important;        }        .table thead th:last-child {          display: none !important;        }        .node-row td {          padding: 0.5rem !important;        }        .node-row td:first-child {          font-size: 0.85rem;          padding-right: 0 !important;          width: calc(100% - 90px) !important;        }        .node-row td:first-child .text-truncate {          max-width: 100% !important;          width: 100% !important;          padding-right: 8px !important;        }        .node-row td:last-child {          padding-left: 0 !important;          width: 90px !important;          position: relative !important;        }        .node-row td:last-child .text-truncate {          display: none !important;        }        /* 节点操作按钮移动端优化 */        .node-actions {          margin: 0 !important;          gap: 2px !important;          justify-content: flex-end !important;          width: 90px !important;          position: absolute !important;          right: 4px !important;          flex-wrap: nowrap !important;          align-items: center !important;        }        .node-actions .btn {          padding: 2px 4px !important;          min-width: 28px !important;          height: 28px !important;          margin: 0 !important;        }        .node-actions .btn i {          font-size: 12px;          line-height: 1;          display: flex !important;          align-items: center !important;          justify-content: center !important;        }        /* 批量操作按钮移动端优化 */        .batch-action-buttons {          flex-wrap: wrap !important;          gap: 0.25rem !important;          width: 100% !important;        }        .batch-action-buttons .btn {          font-size: 0.75rem !important;          padding: 0.25rem 0.5rem !important;          margin: 0 !important;          flex: 1 !important;          min-width: 0 !important;          white-space: nowrap !important;        }        .batch-action-buttons .btn i {          font-size: 0.75rem !important;          margin-right: 0.25rem !important;        }      }

            /* 模态框按钮样式 */      .modal .btn-secondary {        background-color: #e2e8f0;        border-color: #e2e8f0;        color: var(--text-color);      }      .modal .btn-secondary:hover {        background-color: #cbd5e0;        border-color: #cbd5e0;      }      /* 添加通用按钮样式 */
            /* 按钮基础样式 */      .action-btn {        display: inline-flex;        align-items: center;        justify-content: center;        padding: 0.625rem 1.25rem;        font-size: 1rem;        font-weight: 500;        border-radius: 8px;        transition: all 0.2s ease;        min-width: 140px;        height: 42px;        gap: 0.5rem;        line-height: 1;      }      .action-btn i {        font-size: 1rem;        display: inline-flex;        align-items: center;        justify-content: center;        width: 1rem;        height: 1rem;      }      /* 按钮颜色变体 */      .action-btn.btn-primary, .btn-primary {        background-color: var(--primary-color);        border-color: var(--primary-color);        color: white;      }      .action-btn.btn-success, .btn-success {        background-color: var(--success-color);        border-color: var(--success-color);        color: white;      }      .btn-edit {        background-color: #1cc88a;        border-color: #1cc88a;        color: white;      }      /* 按钮悬停效果 */      .action-btn:hover, .btn-edit:hover {        transform: translateY(-1px);        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);      }      .btn-edit:hover {        background-color: #19b57c;        border-color: #19b57c;      }      .btn-edit:focus {        background-color: #19b57c;        border-color: #19b57c;        box-shadow: 0 0 0 0.25rem rgba(28, 200, 138, 0.25);      }      .action-btn:active {        transform: translateY(0);      }      /* 调整容器样式 */      .container {        max-width: 1100px;        padding: 2rem 1rem;      }      .d-flex.justify-content-between.align-items-center.mb-4 {        margin-bottom: 2rem !important;      }            /* 节点列表区域样式 */      .node-list-area {        max-height: 0;        overflow: hidden;        transition: max-height 0.5s cubic-bezier(0.4, 0, 0.2, 1);        background: #fff;        border-radius: 0 0 var(--border-radius-md) var(--border-radius-md);        will-change: max-height;        font-size: 0.875rem;        color: var(--text-color);      }      .node-list-area.expanded {        max-height: none;        overflow: visible;      }      .node-list-area .table-responsive {        transition: transform 0.5s cubic-bezier(0.4, 0, 0.2, 1);        transform-origin: top;      }      .node-list-area .link {        font-size: 0.875rem;        color: var(--text-color-secondary);        text-decoration: none;      }      .node-list-area .link:hover {        text-decoration: underline;      }
    </style>
  </head>
  <body>
    <nav class="navbar navbar-expand navbar-light bg-white">
      <div class="container">
        <a class="navbar-brand" href="#">
          <i class="fas fa-cube"></i>
          Sub-Hub
        </a>
        <div class="navbar-user ms-auto">
          <a href="/${adminPath}/logout" class="logout-btn">
            <i class="fas fa-sign-out-alt me-1"></i>
            退出
          </a>
        </div>
      </div>
    </nav>
    
          <div class="container">
      <div class="subscription-item" style="padding-bottom: 0; border: none; box-shadow: none; margin-bottom: 1rem; background: transparent;">
        <div class="d-flex justify-content-end">
          <button class="btn btn-primary action-btn" data-bs-toggle="modal" data-bs-target="#addSubscriptionModal">
            <i class="fas fa-plus"></i>
            <span>添加订阅</span>
          </button>
        </div>
      </div>
      
      <!-- 订阅列表 -->
      <div class="subscription-list" id="subscriptionList">
        <!-- 订阅项将通过JavaScript动态添加 -->
      </div>
    </div>
    
    <!-- 添加订阅模态框 -->
    <div class="modal fade" id="addSubscriptionModal" tabindex="-1">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">添加新订阅</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <form id="addSubscriptionForm" onsubmit="return false;">
              <div class="mb-3">
                <label class="form-label">订阅名称 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" name="name" required>
                <div class="invalid-feedback">请输入订阅名称</div>
              </div>
              <div class="mb-3">
                <label class="form-label">订阅路径 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" name="path" required pattern="^[a-z0-9-]+$" minlength="5" maxlength="50">
                <div class="form-text">路径只能包含小写字母、数字和连字符，长度在5-50个字符之间</div>
                <div class="path-error text-danger"></div>
              </div>
            </form>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
            <button type="button" class="btn btn-primary" onclick="createSubscription()">创建</button>
          </div>
        </div>
      </div>
    </div>
    
    <!-- 修改添加节点模态框 -->
    <div class="modal fade" id="addNodeModal" tabindex="-1">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">添加节点</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <form id="addNodeForm" onsubmit="return false;">
              <input type="hidden" name="subscriptionPath" value="">
              <div class="mb-3">
                <label class="form-label">节点内容 <span class="text-danger">*</span></label>
                <textarea class="form-control" name="content" rows="6" required placeholder="请输入节点内容，支持以下格式：&#10;1. ss://... &#10;2. vless://...（除Surge） &#10;3. vmess://... &#10;4. trojan://... &#10;5. socks://... &#10;6. hysteria2://... &#10;7. tuic://... &#10;8. snell格式（仅Surge）&#10;9. Base64编码格式"></textarea>
              </div>
            </form>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
            <button type="button" class="btn btn-primary" onclick="createNode()">
              <i class="fas fa-plus me-1"></i>添加
            </button>
          </div>
        </div>
      </div>
    </div>
    
    <!-- 编辑名称和路径模态框 -->
    <div class="modal fade" id="editNameModal" tabindex="-1">
      <div class="modal-dialog">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">编辑订阅信息</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <form id="editNameForm" onsubmit="return false;">
              <input type="hidden" name="originalPath">
              <div class="mb-3">
                <label class="form-label">订阅名称 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" name="name" required>
                <div class="invalid-feedback">请输入订阅名称</div>
              </div>
              <div class="mb-3">
                <label class="form-label">订阅路径 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" name="path" required>
                <div class="form-text">路径只能包含小写字母、数字和连字符，长度在5-50个字符之间</div>
                <div class="path-error text-danger"></div>
              </div>
            </form>
          </div>
          <div class="modal-footer justify-content-between">
            <button type="button" class="btn btn-danger" onclick="confirmDelete()">
              <i class="fas fa-trash"></i> 删除订阅
            </button>
            <div>
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
            <button type="button" class="btn btn-primary" onclick="updateSubscriptionInfo()">保存</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- 编辑节点模态框 -->
    <div class="modal fade" id="editNodeModal" tabindex="-1">
      <div class="modal-dialog modal-lg">
        <div class="modal-content">
          <div class="modal-header">
            <h5 class="modal-title">编辑节点</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <form id="editNodeForm" onsubmit="return false;">
              <input type="hidden" name="subscriptionPath" value="">
              <input type="hidden" name="nodeId" value="">
              <div class="mb-3">
                <label class="form-label">节点内容 <span class="text-danger">*</span></label>
                <textarea class="form-control" name="content" rows="6" required placeholder="请输入节点内容，支持以下格式：&#10;1. ss://... &#10;2. vless://...（除Surge） &#10;3. vmess://... &#10;4. trojan://... &#10;5. socks://... &#10;6. hysteria2://... &#10;7. tuic://... &#10;8. snell格式（仅Surge）&#10;9. Base64编码格式"></textarea>
              </div>
            </form>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
            <button type="button" class="btn btn-primary" onclick="updateNode()">保存</button>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Toast提示 -->
    <div class="toast-container">
      <div id="toast" class="toast align-items-center text-white bg-success" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="d-flex">
          <div class="toast-body" id="toastMessage">
            操作成功!
          </div>
          <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
      </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
      // 定义 adminPath 变量
      const adminPath = '${adminPath}';
            
      // 优化的loadSubscriptions函数
      async function loadSubscriptions() {
        try {
          const response = await fetch('/' + adminPath + '/api/subscriptions');
          if (!response.ok) throw new Error('加载失败');
          const result = await response.json();
          
          if (!result.success) {
            throw new Error(result.message || '加载失败');
          }
          
          const subscriptions = result.data || [];
          const listElement = document.getElementById('subscriptionList');
          listElement.innerHTML = '';
          
          const fragment = document.createDocumentFragment();
          
          for (const sub of subscriptions) {
            const item = document.createElement('div');
            item.className = 'subscription-item';
            item.innerHTML = \`
              <div class="d-flex justify-content-between align-items-start">
                <button class="btn btn-sm btn-link text-primary edit-button" onclick="showEditNameModal('\${sub.path}', '\${sub.name}')">
                  <i class="fas fa-edit"></i>
                </button>
                <div class="subscription-content">
                  <div class="d-flex align-items-center">
                    <h5 class="subscription-name mb-1">\${sub.name}</h5>
                    <span class="node-count ms-2"><i class="fas fa-server"></i>\${sub.nodeCount}</span>
                  </div>
                  <div class="link-label">
                    <small>
                      <span>
                        <span class="address-label">订阅地址1：</span> <a href="/\${sub.path}" target="_blank">/\${sub.path}</a>
                      </span>
                      <span>
                        <span class="address-label">订阅地址2：</span> <a href="/\${sub.path}/v2ray" target="_blank">/\${sub.path}/v2ray</a>
                      </span>
                      <span>
                        <span class="address-label">订阅地址3：</span> <a href="/\${sub.path}/surge" target="_blank">/\${sub.path}/surge</a>
                      </span>
                      <span>
                        <span class="address-label">订阅地址4：</span> <a href="/\${sub.path}/clash" target="_blank">/\${sub.path}/clash</a>
                      </span>
                    </small>
                  </div>
                </div>
                <div class="subscription-actions">
                  <button class="btn btn-success action-btn" onclick="showAddNodeModal('\${sub.path}')">
                    <i class="fas fa-plus"></i>
                    <span>添加节点</span>
                  </button>
                  <button class="btn btn-primary action-btn" onclick="showNodeList('\${sub.path}')">
                    <i class="fas fa-list"></i>
                    <span>节点列表</span>
                  </button>
                </div>
              </div>
              <div class="node-list-area" id="node-list-\${sub.path}">
                <div class="table-responsive mt-3">
                  <table class="table">
                    <thead>
                      <tr>
                        <th style="min-width: 300px; width: 35%; padding-left: 0.75rem;">节点名称</th>
                        <th style="padding-left: 4.5rem;">节点链接</th>
                      </tr>
                    </thead>
                    <tbody></tbody>
                  </table>
                  <div class="d-flex justify-content-between align-items-center mt-3 px-2 pb-2">
                    <div class="batch-operation-buttons" id="batch-operation-buttons-\${sub.path}">
                      <button class="btn btn-primary btn-sm rounded-3" onclick="enterBatchMode('\${sub.path}')" id="batch-mode-btn-\${sub.path}" style="padding: 0.5rem 1rem;">
                        <i class="fas fa-tasks me-1"></i>批量操作
                      </button>
                    </div>
                    <div class="batch-action-buttons" id="batch-action-buttons-\${sub.path}" style="display: none;">
                      <button class="btn btn-success btn-sm rounded-3 me-2" onclick="executeBatchStatusChange('\${sub.path}', true)" style="padding: 0.5rem 1rem;">
                        <i class="fas fa-toggle-on me-1"></i>启用
                      </button>
                      <button class="btn btn-warning btn-sm rounded-3 me-2" onclick="executeBatchStatusChange('\${sub.path}', false)" style="padding: 0.5rem 1rem;">
                        <i class="fas fa-toggle-off me-1"></i>禁用
                      </button>
                      <button class="btn btn-danger btn-sm rounded-3 me-2" onclick="executeBatchDelete('\${sub.path}')" style="padding: 0.5rem 1rem;">
                        <i class="fas fa-trash-alt me-1"></i>删除
                      </button>
                      <button class="btn btn-outline-secondary btn-sm rounded-3 me-2" onclick="toggleSelectAll('\${sub.path}')" id="select-all-btn-\${sub.path}" style="padding: 0.5rem 1rem;">
                        <i class="fas fa-check-square me-1"></i>全选
                      </button>
                      <button class="btn btn-secondary btn-sm rounded-3" onclick="exitBatchMode('\${sub.path}')" style="padding: 0.5rem 1rem;">
                        <i class="fas fa-times me-1"></i>取消
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            \`;
            fragment.appendChild(item);
          }
          
          listElement.appendChild(fragment);
        } catch (error) {
          showToast('加载订阅列表失败: ' + error.message, 'danger');
        }
      }
      
      // 页面加载完成后，加载订阅列表
      window.addEventListener('load', loadSubscriptions);

      // 进入批量操作模式
      function enterBatchMode(subscriptionPath) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        const checkboxes = nodeListArea.querySelectorAll('.node-checkbox');
        const operationButtons = document.getElementById('batch-operation-buttons-' + subscriptionPath);
        const actionButtons = document.getElementById('batch-action-buttons-' + subscriptionPath);
        
        // 显示勾选框
        checkboxes.forEach(checkbox => {
          checkbox.style.display = 'inline-block';
        });
        
        // 切换按钮显示
        operationButtons.style.display = 'none';
        actionButtons.style.display = 'flex';
        
        // 标记为批量模式
        nodeListArea.classList.add('batch-mode');
        
        // 重置所有勾选框
        checkboxes.forEach(cb => {
          cb.checked = false;
        });
        
        // 重置全选按钮状态
        resetSelectAllButton(subscriptionPath);
        
        showToast('请选择要操作的节点，然后选择对应的操作', 'info');
      }

      // 退出批量操作模式
      function exitBatchMode(subscriptionPath) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        const checkboxes = nodeListArea.querySelectorAll('.node-checkbox');
        const operationButtons = document.getElementById('batch-operation-buttons-' + subscriptionPath);
        const actionButtons = document.getElementById('batch-action-buttons-' + subscriptionPath);
        
        // 隐藏勾选框
        checkboxes.forEach(checkbox => {
          checkbox.style.display = 'none';
        });
        
        // 切换按钮显示
        operationButtons.style.display = 'flex';
        actionButtons.style.display = 'none';
        
        // 取消批量模式标记
        nodeListArea.classList.remove('batch-mode');
      }

      // 重置全选按钮状态
      function resetSelectAllButton(subscriptionPath) {
        const selectAllBtn = document.getElementById('select-all-btn-' + subscriptionPath);
        if (selectAllBtn) {
          selectAllBtn.innerHTML = '<i class="fas fa-check-square me-1"></i>全选';
        }
      }

      // 全选/取消全选功能
      function toggleSelectAll(subscriptionPath) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        const checkboxes = nodeListArea.querySelectorAll('.node-checkbox');
        const selectAllBtn = document.getElementById('select-all-btn-' + subscriptionPath);
        
        // 检查当前是否为全选状态
        const checkedCount = nodeListArea.querySelectorAll('.node-checkbox:checked').length;
        const isAllSelected = checkedCount === checkboxes.length && checkboxes.length > 0;
        
        // 切换选择状态
        checkboxes.forEach(checkbox => {
          checkbox.checked = !isAllSelected;
        });
        
        // 更新按钮状态
        if (isAllSelected) {
          selectAllBtn.innerHTML = '<i class="fas fa-check-square me-1"></i>全选';
        } else {
          selectAllBtn.innerHTML = '<i class="fas fa-minus-square me-1"></i>取消';
        }
      }

      // 执行批量删除
      async function executeBatchDelete(subscriptionPath) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        const checkedNodes = nodeListArea.querySelectorAll('.node-checkbox:checked');
        
        if (checkedNodes.length === 0) {
          showToast('请选择要删除的节点', 'warning');
          return;
        }
        
        if (!confirm(\`确定要删除选中的 \${checkedNodes.length} 个节点吗？\`)) {
          return;
        }
        
        try {
          let successCount = 0;
          let failCount = 0;
          
          // 显示进度提示
          showToast('正在删除节点...', 'info');
          
          // 批量删除所选节点
          for (const checkbox of checkedNodes) {
            const nodeId = checkbox.value;
            try {
              const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + nodeId, {
                method: 'DELETE',
                headers: { 
                  'Content-Type': 'application/json',
                  'X-Requested-With': 'XMLHttpRequest'
                }
              });
              
              if (response.ok) {
                successCount++;
              } else {
                failCount++;
              }
            } catch (error) {
              console.error('删除节点失败:', error);
              failCount++;
            }
          }
          
          // 显示删除结果
          if (failCount === 0) {
            showToast(\`成功删除 \${successCount} 个节点\`, 'success');
          } else {
            showToast(\`删除完成：成功 \${successCount} 个，失败 \${failCount} 个\`, 'warning');
          }
          
          // 退出批量操作模式
          exitBatchMode(subscriptionPath);
          
          // 重新加载节点列表和订阅信息
          await loadNodeList(subscriptionPath);
          await loadSubscriptions();
          
        } catch (error) {
          console.error('批量删除失败:', error);
          showToast('批量删除失败: ' + error.message, 'danger');
        }
      };

      // 执行批量状态切换
      async function executeBatchStatusChange(subscriptionPath, enabled) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        const checkedNodes = nodeListArea.querySelectorAll('.node-checkbox:checked');
        
        if (checkedNodes.length === 0) {
          showToast('请先选择要操作的节点', 'warning');
          return;
        }
        
        const action = enabled ? '启用' : '禁用';
        if (!confirm('确定要' + action + '选中的 ' + checkedNodes.length + ' 个节点吗？')) {
          return;
        }
        
        try {
          let successCount = 0;
          let failCount = 0;
          
          // 显示进度提示
          showToast('正在' + action + '节点...', 'info');
          
          // 批量操作所选节点
          for (const checkbox of checkedNodes) {
            const nodeId = checkbox.value;
            try {
              const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + nodeId, {
                method: 'PATCH',
                headers: { 
                  'Content-Type': 'application/json',
                  'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({ enabled })
              });
              
              if (response.ok) {
                successCount++;
              } else {
                failCount++;
              }
            } catch (error) {
              console.error('操作节点失败:', error);
              failCount++;
            }
          }
          
          // 显示操作结果
          if (failCount === 0) {
            showToast('成功' + action + ' ' + successCount + ' 个节点', 'success');
          } else {
            showToast(action + '完成：成功 ' + successCount + ' 个，失败 ' + failCount + ' 个', 'warning');
          }
          
          // 退出批量操作模式
          exitBatchMode(subscriptionPath);
          
          // 重新加载节点列表和订阅信息
          await loadNodeList(subscriptionPath);
          await loadSubscriptions();
          
        } catch (error) {
          console.error('批量操作失败:', error);
          showToast('批量' + action + '失败: ' + error.message, 'danger');
        }
      }
      
      // 显示添加节点模态框
      function showAddNodeModal(subscriptionPath) {
        const modal = document.getElementById('addNodeModal');
        const form = document.getElementById('addNodeForm');
        
        // 重置表单
        form.reset();
        
        // 设置订阅路径
        const pathInput = form.querySelector('[name="subscriptionPath"]');
        if (pathInput) {
          pathInput.value = subscriptionPath;
        }

        // 显示模态框
        const modalInstance = new bootstrap.Modal(modal);
        modalInstance.show();
      }

      

      // 修改创建节点函数
      async function createNode() {
        try {
          const form = document.getElementById('addNodeForm');
          if (!form) {
            throw new Error('找不到表单元素');
          }

          const formData = new FormData(form);
          const subscriptionPath = formData.get('subscriptionPath');
          const name = formData.get('name')?.trim();
          let content = formData.get('content')?.trim();

          if (!subscriptionPath) {
            throw new Error('缺少订阅路径');
          }

          if (!content) {
            throw new Error('请填写节点内容');
          }

          // 分割成行
          const lines = content.split(/\\r?\\n/);
          const validNodes = [];

          // 处理每一行
          for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine) continue;

            // 检查是否是Base64编码的完整配置
            try {
              const decodedContent = safeBase64DecodeFrontend(trimmedLine);
              // 如果解码成功，检查是否包含多个节点
              const decodedLines = decodedContent.split(/\\r?\\n/);
              for (const decodedLine of decodedLines) {
                if (decodedLine.trim() && isValidNodeLink(decodedLine.trim())) {
                  validNodes.push({
                    name: name || extractNodeNameFrontend(decodedLine.trim()),
                    content: decodedLine.trim()
                  });
                }
              }
            } catch (e) {
              // 如果不是Base64编码，直接检查是否是有效的节点链接
              if (isValidNodeLink(trimmedLine)) {
                validNodes.push({
                  name: name || extractNodeNameFrontend(trimmedLine),
                  content: trimmedLine
                });
              }
            }
          }

          if (validNodes.length === 0) {
            throw new Error('未找到有效的节点链接');
          }

          // 批量创建节点，按顺序添加
          const results = [];
          const timestamp = Date.now(); // 使用时间戳作为基础序号
          
          for (let i = 0; i < validNodes.length; i++) {
            const node = validNodes[i];
            try {
              // 创建节点，使用时间戳+索引作为顺序值
              const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes', {
                method: 'POST',
                headers: { 
                  'Content-Type': 'application/json',
                  'X-Requested-With': 'XMLHttpRequest'
                },
                body: JSON.stringify({
                  name: node.name,
                  content: node.content,
                  type: getNodeType(node.content),
                  order: timestamp + i  // 使用时间戳确保顺序唯一且递增
                })
              });
              
              const result = await response.json();
              results.push({ success: response.ok, message: result.message, link: node.content, order: i });
            } catch (error) {
              results.push({ success: false, message: error.message, link: node.content, order: i });
            }
          }

          // 按原始顺序排序结果
          results.sort((a, b) => a.order - b.order);

          // 统计结果
          const successful = results.filter(r => r.success).length;
          const failed = results.filter(r => !r.success).length;

          // 显示结果
          if (validNodes.length === 1) {
            showToast(successful > 0 ? '节点添加成功' : '节点添加失败', successful > 0 ? 'success' : 'danger');
          } else {
            showToast(\`添加完成：成功 \${successful} 个，失败 \${failed} 个\`, successful > 0 ? 'success' : 'warning');
          }

          // 关闭模态框
          const modal = document.getElementById('addNodeModal');
          if (modal) {
            const modalInstance = bootstrap.Modal.getInstance(modal);
            if (modalInstance) {
              modalInstance.hide();
            }
          }

          // 重置表单
          form.reset();
          
          // 刷新订阅列表
          await loadSubscriptions();
          if (successful > 0) {
            await loadNodeList(subscriptionPath);
          }
          
        } catch (error) {
          console.error('添加节点失败:', error);
          showToast('添加节点失败: ' + error.message, 'danger');
        }
      }

      // 提取节点名称（前端版本 - 复用后端实现）
      function extractNodeNameFrontend(nodeLink) {
        if (!nodeLink) return '未命名节点';
        
        // 处理snell节点
        if(nodeLink.includes(NODE_TYPES_FRONTEND.SNELL)) {
          const name = nodeLink.split('=')[0].trim();
          return name || '未命名节点';
        }
        
        // 处理 VMess 链接
        if (nodeLink.toLowerCase().startsWith(NODE_TYPES_FRONTEND.VMESS)) {
          try {
            const config = JSON.parse(safeBase64DecodeFrontend(nodeLink.substring(8)));
            if (config.ps) {
              return safeUtf8DecodeFrontend(config.ps);
            }
          } catch {}
          return '未命名节点';
        }

        // 处理其他使用哈希标记名称的链接类型（SS、TROJAN、VLESS、SOCKS、Hysteria2、TUIC等）
        const hashIndex = nodeLink.indexOf('#');
        if (hashIndex !== -1) {
          try {
            return decodeURIComponent(nodeLink.substring(hashIndex + 1));
          } catch {
            return nodeLink.substring(hashIndex + 1) || '未命名节点';
          }
        }
        return '未命名节点';
      }

      // 节点类型常量定义（复用后端定义）
      const NODE_TYPES_FRONTEND = {
        SS: 'ss://',
        VMESS: 'vmess://',
        TROJAN: 'trojan://',
        VLESS: 'vless://',
        SOCKS: 'socks://',
        HYSTERIA2: 'hysteria2://',
        TUIC: 'tuic://',
        SNELL: 'snell,'
      };

      // 检查是否是有效的节点链接
      function isValidNodeLink(link) {
        const lowerLink = link.toLowerCase();
        // 检查snell格式
        if(lowerLink.includes('=') && lowerLink.includes('snell,')) {
          const parts = link.split('=')[1]?.trim().split(',');
          return parts && parts.length >= 4 && parts[0].trim() === 'snell';
        }
        return Object.values(NODE_TYPES_FRONTEND).some(prefix => lowerLink.startsWith(prefix));
      }

      // 获取节点类型
      function getNodeType(link) {
        const lowerLink = link.toLowerCase();
        if(lowerLink.includes('=') && lowerLink.includes('snell,')) {
          return 'snell';
        }
        return Object.entries(NODE_TYPES_FRONTEND).find(([key, prefix]) => 
          lowerLink.startsWith(prefix)
        )?.[0].toLowerCase() || '';
      }

      // 安全的UTF-8字符串解码函数（前端版本 - 复用后端实现）
      function safeUtf8DecodeFrontend(str) {
        if (!str) return str;
        
        try {
          // 方法1：使用escape + decodeURIComponent
          return decodeURIComponent(escape(str));
        } catch (e1) {
          try {
            // 方法2：直接使用decodeURIComponent
            return decodeURIComponent(str);
          } catch (e2) {
            try {
              // 方法3：使用TextDecoder（如果支持）
              if (typeof TextDecoder !== 'undefined') {
                const encoder = new TextEncoder();
                const decoder = new TextDecoder('utf-8');
                return decoder.decode(encoder.encode(str));
              }
            } catch (e3) {
              // 如果所有方法都失败，返回原始字符串
              return str;
            }
            return str;
          }
        }
      }

      

      // 显示节点列表
      async function showNodeList(subscriptionPath) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        if (!nodeListArea) {
          console.error('找不到节点列表区域');
          return;
        }

        const isHidden = !nodeListArea.classList.contains('expanded');
        let expandedSubs = JSON.parse(localStorage.getItem('expandedSubscriptions') || '[]');
        
        if (isHidden) {
          // 立即添加展开类名触发动画
          nodeListArea.classList.add('expanded');
          
          // 更新展开状态
          if (!expandedSubs.includes(subscriptionPath)) {
            expandedSubs.push(subscriptionPath);
            localStorage.setItem('expandedSubscriptions', JSON.stringify(expandedSubs));
          }

          // 同时开始加载数据
          loadNodeList(subscriptionPath).catch(error => {
            console.error('加载节点列表失败:', error);
            showToast('加载节点列表失败: ' + error.message, 'danger');
          });
        } else {
          nodeListArea.classList.remove('expanded');
          expandedSubs = expandedSubs.filter(path => path !== subscriptionPath);
          localStorage.setItem('expandedSubscriptions', JSON.stringify(expandedSubs));
        }
      }

      // 修改加载节点列表函数
      async function loadNodeList(subscriptionPath) {
        const nodeListArea = document.getElementById('node-list-' + subscriptionPath);
        if (!nodeListArea) {
          throw new Error('找不到节点列表区域');
        }

        const tbody = nodeListArea.querySelector('tbody');
        
        // 先显示加载中的提示
        tbody.innerHTML = '<tr><td colspan="2" class="text-center py-4"><i class="fas fa-spinner fa-spin me-2"></i>加载中...</td></tr>';

        try {
          const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes');
          if (!response.ok) throw new Error('加载失败');
          
          const result = await response.json();
          if (!result.success) {
            throw new Error(result.message || '加载失败');
          }
          
          const nodes = result.data || [];
          
          // 构建节点列表HTML
          const nodesHtml = nodes.map(node => {
            const nodeLink = node.original_link;
            const escapedNodeLink = nodeLink
              .replace(/&/g, '&amp;')
              .replace(/'/g, '\\\'')
              .replace(/"/g, '\\"');
            const isEnabled = node.enabled === 1;
            
            return \`
                  <tr class="node-row" data-id="\${node.id}" data-order="\${node.node_order}" data-enabled="\${isEnabled ? '1' : '0'}">
      <td class="align-middle">
        <div class="d-flex align-items-center">
          <input class="node-checkbox me-2" type="checkbox" value="\${node.id}" 
            data-subscription="\${subscriptionPath}" style="display: none;">
          <div class="text-nowrap text-truncate \${!isEnabled ? 'text-danger' : ''}" style="max-width: 320px; \${!isEnabled ? 'text-decoration: line-through;' : ''}" title="\${node.name}">
            \${node.name}
          </div>
        </div>
      </td>
                <td class="align-middle">
                  <div class="d-flex justify-content-between align-items-center" style="gap: 8px;">
                              <div class="text-nowrap text-truncate \${!isEnabled ? 'text-danger' : ''}" style="max-width: 400px; margin-left: 4rem; \${!isEnabled ? 'text-decoration: line-through;' : ''}" title="\${nodeLink}">
            \${nodeLink}
          </div>
                    <div class="node-actions d-flex" style="flex-shrink: 0; gap: 4px;">
                      <button class="btn btn-sm btn-edit" onclick="showEditNodeModal('\${subscriptionPath}', '\${node.id}', '\${escapedNodeLink}')" title="编辑节点">
                        <i class="fas fa-edit"></i>
                      </button>
                      <button class="btn btn-sm btn-primary" onclick="copyToClipboard('\${escapedNodeLink}')" title="复制链接">
                        <i class="fas fa-copy"></i>
                      </button>
                      <button class="btn btn-sm btn-danger" onclick="deleteNode('\${subscriptionPath}', \${node.id})" title="删除节点">
                        <i class="fas fa-trash"></i>
                      </button>
                    </div>
                  </div>
                </td>
              </tr>
            \`;
          }).join('');
          
          // 更新节点列表内容
          tbody.innerHTML = nodesHtml || '<tr><td colspan="2" class="text-center py-4">暂无节点</td></tr>';

          // 初始化拖拽排序
          if (nodes.length > 0) {
            // 检查是否为移动设备
            const isMobile = window.innerWidth <= 767;
            
            // 只在非移动设备上初始化排序
            if (!isMobile) {
              initializeSortable(tbody, subscriptionPath);
            }
          }
        } catch (error) {
          tbody.innerHTML = \`<tr><td colspan="2" class="text-center py-4 text-danger">
            <i class="fas fa-exclamation-circle me-2"></i>\${error.message}
          </td></tr>\`;
          throw error;
        }
      }

      // 初始化拖拽排序功能
      function initializeSortable(tbody, subscriptionPath) {
        new Sortable(tbody, {
          animation: 150,
          handle: '.node-row',
          ghostClass: 'sortable-ghost',
          dragClass: 'sortable-drag',
          onEnd: async function(evt) {
            try {
              const rows = Array.from(tbody.querySelectorAll('.node-row'));
              const newOrders = rows.map((row, index) => ({
                id: parseInt(row.dataset.id),
                order: index
              }));

              await updateNodeOrder(subscriptionPath, newOrders);
              showToast('节点排序已更新');
            } catch (error) {
              console.error('更新节点排序失败:', error);
              showToast('更新节点排序失败: ' + error.message, 'danger');
              // 重新加载列表以恢复原始顺序
              await loadNodeList(subscriptionPath);
            }
          }
        });
      }

      // 删除节点
      async function deleteNode(subscriptionPath, nodeId) {
        if (!confirm('确定要删除这个节点吗？')) return;
        
        try {
          const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + nodeId, {
            method: 'DELETE',
            headers: { 
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            }
          });
          
          const result = await response.json();
          
          if (!response.ok) {
            throw new Error(result.message || '删除失败');
          }
          
          showToast('节点已删除');
          await loadNodeList(subscriptionPath);
          await loadSubscriptions();
        } catch (error) {
          showToast('删除节点失败: ' + error.message, 'danger');
        }
      }

      // 添加创建订阅函数
      async function createSubscription() {
        const form = document.getElementById('addSubscriptionForm');
        const formData = new FormData(form);
        const name = formData.get('name').trim();
        const path = formData.get('path').trim();
        
        if (!name) {
          showToast('请输入订阅名称', 'danger');
          form.querySelector('[name="name"]').focus();
          return;
        }

                  if (!path || !validateSubscriptionPathFrontend(path)) {
          const pathInput = form.querySelector('[name="path"]');
          pathInput.classList.add('is-invalid');
          pathInput.classList.remove('is-valid');
          form.querySelector('.path-error').textContent = '路径格式不正确';
          form.querySelector('.path-error').style.display = 'block';
          pathInput.focus();
          return;
        }

        try {
          const response = await fetch('/' + adminPath + '/api/subscriptions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ name, path })
          });
          
          const result = await response.json();
          
          if (!response.ok) throw new Error(result.message || '创建失败');
          
          showToast('订阅创建成功');
          bootstrap.Modal.getInstance(document.getElementById('addSubscriptionModal')).hide();
          form.reset();
          await loadSubscriptions();
        } catch (error) {
          showToast('创建失败: ' + error.message, 'danger');
        }
      }
      
      // 添加显示Toast提示函数
      function showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        
        // 设置消息
        toastMessage.textContent = message;
        
        // 设置类型
        toast.className = toast.className.replace(/bg-\w+/, '');
        toast.classList.add('bg-' + type);
        
        // 显示Toast
        const bsToast = new bootstrap.Toast(toast);
        bsToast.show();
            }            
      // 显示编辑名称模态框
      function showEditNameModal(path, name) {
        const form = document.getElementById('editNameForm');
        form.querySelector('input[name="originalPath"]').value = path;
        form.querySelector('input[name="name"]').value = name;
        form.querySelector('input[name="path"]').value = path;
        
        const modal = new bootstrap.Modal(document.getElementById('editNameModal'));
        modal.show();
      }
      
      // 更新订阅信息
      async function updateSubscriptionInfo() {
        const form = document.getElementById('editNameForm');
        const originalPath = form.querySelector('input[name="originalPath"]').value;
        const nameInput = form.querySelector('input[name="name"]');
        const pathInput = form.querySelector('input[name="path"]');
        const pathError = form.querySelector('.path-error');
        
        try {
          // 验证输入
          if (!nameInput.value.trim()) {
            showToast('请输入订阅名称', 'danger');
            nameInput.focus();
            return;
          }

          // 验证路径格式
          const path = pathInput.value.trim();
          if (!validateSubscriptionPathFrontend(path)) {
            pathInput.classList.add('is-invalid');
            pathInput.classList.remove('is-valid');
            pathError.textContent = '路径格式不正确';
            pathError.style.display = 'block';
            pathInput.focus();
            return;
          }

          // 如果路径被修改，检查新路径是否已存在
          if (path !== originalPath) {
            const checkResponse = await fetch('/' + adminPath + '/api/subscriptions/' + path);
            if (checkResponse.ok) {
              pathInput.classList.add('is-invalid');
              pathInput.classList.remove('is-valid');
              pathError.textContent = '该路径已被使用';
              pathError.style.display = 'block';
              pathInput.focus();
              return;
            }
          }

          const response = await fetch('/' + adminPath + '/api/subscriptions/' + originalPath, {
            method: 'PUT',
            headers: { 
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
              name: nameInput.value.trim(),
              path: path,
              action: 'update_info'
            })
          });

          const result = await response.json();
          
          if (!response.ok) {
            throw new Error(result.message || '更新失败');
          }

          showToast('订阅信息已更新');
          bootstrap.Modal.getInstance(document.getElementById('editNameModal')).hide();
          await loadSubscriptions();
        } catch (error) {
          console.error('更新订阅信息失败:', error);
          showToast('更新失败: ' + error.message, 'danger');
        }
      }

      // 添加确认删除函数
      async function confirmDelete() {
        try {
          const form = document.getElementById('editNameForm');
          const path = form.querySelector('input[name="originalPath"]').value;
          
          if (!path) {
            showToast('无效的订阅路径', 'danger');
            return;
          }

          if (!confirm('确定要删除这个订阅吗？')) {
            return;
          }

          const response = await fetch('/' + adminPath + '/api/subscriptions/' + path, {
            method: 'DELETE',
            headers: {
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            }
          });

          if (!response.ok) {
            const result = await response.json();
            throw new Error(result.message || '删除失败');
          }

          // 关闭编辑模态框
          const editModal = bootstrap.Modal.getInstance(document.getElementById('editNameModal'));
          if (editModal) {
            editModal.hide();
          }

          showToast('订阅已删除');
          await loadSubscriptions();
        } catch (error) {
          console.error('删除失败:', error);
          showToast('删除失败: ' + error.message, 'danger');
        }
      }

      // 表单验证工具函数（复用后端实现）
      function validateSubscriptionPathFrontend(path) {
        return /^[a-z0-9-]{5,50}$/.test(path);
      }

      // 添加复制到剪贴板函数
      function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
          showToast('已复制到剪贴板');
        }).catch(() => {
          showToast('复制失败', 'danger');
        });
      }

            // 显示编辑节点模态框
      function showEditNodeModal(subscriptionPath, nodeId, nodeContent) {
        const modal = document.getElementById('editNodeModal');
        const form = document.getElementById('editNodeForm');
        
        if (!modal || !form) {
          showToast('显示编辑模态框失败：找不到必要的页面元素', 'danger');
          return;
        }

        // 设置表单值
        form.querySelector('[name="subscriptionPath"]').value = subscriptionPath;
        form.querySelector('[name="nodeId"]').value = nodeId;
        form.setAttribute('data-original-content', nodeContent);
        form.querySelector('[name="content"]').value = nodeContent;

        // 显示模态框
        new bootstrap.Modal(modal).show();
      }

      // 更新节点
      async function updateNode() {
        const form = document.getElementById('editNodeForm');
        const formData = new FormData(form);
        const subscriptionPath = formData.get('subscriptionPath');
        const nodeId = formData.get('nodeId');
        const content = formData.get('content')?.trim();
        const originalContent = form.getAttribute('data-original-content');
        
        if (!subscriptionPath || !nodeId || !content) {
          showToast('请填写完整的节点信息', 'danger');
          return;
        }

        // 检查内容是否被修改
        if (content === originalContent) {
          showToast('节点内容未修改');
          bootstrap.Modal.getInstance(document.getElementById('editNodeModal'))?.hide();
          return;
        }

        try {
          const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/' + nodeId, {
            method: 'PUT',
            headers: { 
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ content })
          });

          const result = await response.json();
          if (!response.ok) throw new Error(result.message || '更新失败');
          
          showToast('节点更新成功');
          bootstrap.Modal.getInstance(document.getElementById('editNodeModal'))?.hide();
          form.reset();
          
          // 刷新数据
          await Promise.all([
            loadSubscriptions(),
            loadNodeList(subscriptionPath)
          ]);
          
        } catch (error) {
          showToast('更新节点失败: ' + error.message, 'danger');
        }
      }
      // 修改前端的排序处理代码
      async function updateNodeOrder(subscriptionPath, orders) {
        try {
          const response = await fetch('/' + adminPath + '/api/subscriptions/' + subscriptionPath + '/nodes/reorder', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({ orders })
          });

          const result = await response.json();
          
          if (!result.success) {
            throw new Error(result.message || '保存排序失败');
          }
          
          return result;
        } catch (error) {
          console.error('更新节点排序失败:', error);
        } finally {
          // 无论成功还是失败都重新加载节点列表
          await loadNodeList(subscriptionPath);
        }
      }

      // 安全的Base64解码函数（前端版本 - 复用后端实现）
      function safeBase64DecodeFrontend(str) {
        try {
          // 方法1：使用atob解码，然后正确处理UTF-8编码
          const decoded = atob(str);
          // 将解码结果转换为UTF-8字符串
          const bytes = [];
          for (let i = 0; i < decoded.length; i++) {
            bytes.push(decoded.charCodeAt(i));
          }
          // 使用TextDecoder正确解码UTF-8字符
          if (typeof TextDecoder !== 'undefined') {
            const decoder = new TextDecoder('utf-8');
            return decoder.decode(new Uint8Array(bytes));
          } else {
            // 如果没有TextDecoder，使用escape + decodeURIComponent
            let utf8String = '';
            for (let i = 0; i < bytes.length; i++) {
              utf8String += String.fromCharCode(bytes[i]);
            }
            return decodeURIComponent(escape(utf8String));
          }
        } catch (e) {
          try {
            // 方法2：直接使用atob，可能适用于简单ASCII字符
            return atob(str);
          } catch (e2) {
            // 如果Base64解码失败，返回原字符串
            return str;
          }
        }
      }

    </script>
  </body>
  </html>`;

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
}

// 通用响应头
const JSON_HEADERS = { 'Content-Type': 'application/json' };

// 通用响应创建函数
function createResponse(success, message, data = null, status = success ? 200 : 500) {
  return new Response(
    JSON.stringify({
      success,
      message,
      ...(data && { data })
    }), 
    {
      headers: JSON_HEADERS,
      status
    }
  );
}

// 错误响应函数
const createErrorResponse = (message, status = 500) => 
  createResponse(false, message, null, status);

// 成功响应函数
const createSuccessResponse = (data = null, message = '操作成功') => 
  createResponse(true, message, data);

// 修改获取订阅列表函数
async function handleGetSubscriptions(env) {
  const { results } = await env.DB.prepare(`
    SELECT 
      s.path,
      s.name,
      COUNT(n.id) as nodeCount
    FROM subscriptions s
    LEFT JOIN nodes n ON s.id = n.subscription_id
    GROUP BY s.id
    ORDER BY s.id ASC
  `).all();
  
  const subscriptions = results.map(item => ({
    name: item.name,
    path: item.path,
    nodeCount: item.nodeCount || 0
  }));

  return createSuccessResponse(subscriptions);
}

// 添加获取节点列表的函数
async function handleGetNodes(env, subscriptionPath) {
  const { results } = await env.DB.prepare(`
    SELECT 
      n.id,
      n.name,
      n.original_link,
      n.node_order,
      COALESCE(n.enabled, 1) as enabled
    FROM nodes n
    JOIN subscriptions s ON n.subscription_id = s.id
    WHERE s.path = ?
    ORDER BY n.node_order ASC
  `).bind(subscriptionPath).all();
  
  return createSuccessResponse(results || []);
}

// 添加创建节点的函数
async function handleCreateNode(request, env, subscriptionPath) {
  const nodeData = await request.json();
  
  if (!nodeData.content) {
    return createErrorResponse('缺少节点内容', 400);
  }
  
  const { results: subResults } = await env.DB.prepare(
    "SELECT id FROM subscriptions WHERE path = ?"
  ).bind(subscriptionPath).all();
  
  if (!subResults?.length) {
    return createErrorResponse('订阅不存在', 404);
  }
  
  const subscriptionId = subResults[0].id;
  let originalLink = nodeData.content.trim();
  
  // 尝试Base64解码
  try {
    const decodedContent = safeBase64Decode(originalLink);
    // 检查解码后的内容是否是有效的节点链接
    if (Object.values(NODE_TYPES).some(prefix => 
      decodedContent.startsWith(prefix) && prefix !== NODE_TYPES.SNELL)) {
      originalLink = decodedContent.trim();
    }
  } catch (e) {
    // 不是Base64格式，继续使用原始内容
  }

  // 验证节点类型
  const lowerContent = originalLink.toLowerCase();
  const isSnell = lowerContent.includes('=') && lowerContent.includes('snell,');
  if (!['ss://', 'vmess://', 'trojan://', 'vless://', 'socks://', 'hysteria2://', 'tuic://'].some(prefix => lowerContent.startsWith(prefix)) && !isSnell) {
    return createErrorResponse('不支持的节点格式', 400);
  }
  
  // 从节点链接中提取名称
  let nodeName = extractNodeName(originalLink);
  
  // 直接使用提供的order值
  const nodeOrder = nodeData.order;

  // 直接插入新节点，不更新其他节点的顺序
  await env.DB.prepare(`
    INSERT INTO nodes (subscription_id, name, original_link, node_order, enabled) 
    VALUES (?, ?, ?, ?, 1)
  `).bind(subscriptionId, nodeName, originalLink, nodeOrder).run();

  return createSuccessResponse(null, '节点创建成功');
}

// 添加删除节点的函数
async function handleDeleteNode(env, subscriptionPath, nodeId) {
  try {
    const result = await env.DB.prepare(`
      DELETE FROM nodes
      WHERE id = ? AND subscription_id = (
        SELECT id FROM subscriptions WHERE path = ? LIMIT 1
      )
    `).bind(nodeId, subscriptionPath).run();

    return createSuccessResponse(null, '节点已删除');
  } catch (error) {
    return createErrorResponse('删除节点失败: ' + error.message);
  }
}

// 添加切换节点状态的函数
async function handleToggleNode(env, subscriptionPath, nodeId, request) {
  try {
    const { enabled } = await request.json();
    
    // 验证enabled值
    if (typeof enabled !== 'boolean') {
      return createErrorResponse('无效的状态值', 400);
    }
    
    // 更新节点状态
    const result = await env.DB.prepare(`
      UPDATE nodes 
      SET enabled = ?
      WHERE id = ? AND subscription_id = (
        SELECT id FROM subscriptions WHERE path = ? LIMIT 1
      )
    `).bind(enabled ? 1 : 0, nodeId, subscriptionPath).run();

    if (result.changes === 0) {
      return createErrorResponse('节点不存在或更新失败', 404);
    }

    return createSuccessResponse(null, '节点已' + (enabled ? '启用' : '禁用'));
  } catch (error) {
    return createErrorResponse('切换节点状态失败: ' + error.message);
  }
}

// 生成订阅内容
async function generateSubscriptionContent(env, path) {
  if (!path?.trim()) return '';

  const { results } = await env.DB.prepare(`
    SELECT GROUP_CONCAT(n.original_link, CHAR(10)) as content
    FROM nodes n
    JOIN subscriptions s ON n.subscription_id = s.id
    WHERE s.path = ? AND n.original_link IS NOT NULL AND (n.enabled IS NULL OR n.enabled = 1)
    GROUP BY s.id
    ORDER BY n.node_order ASC
  `).bind(path).all();

  return results?.[0]?.content || '';
}

// 解析SIP002格式
function parseSIP002Format(ssLink) {
  try {
    const [base, name = ''] = ssLink.split('#');
    if (!base.startsWith(NODE_TYPES.SS)) return null;
    
    const prefixRemoved = base.substring(5);
    const atIndex = prefixRemoved.indexOf('@');
    if (atIndex === -1) return null;
    
    // 正确解析服务器地址和端口，支持IPv6
    const serverPortPart = prefixRemoved.substring(atIndex + 1);
    let server, port;
    
    // 检查是否是IPv6地址（用方括号包围）
    if (serverPortPart.startsWith('[')) {
      const closeBracketIndex = serverPortPart.indexOf(']');
      if (closeBracketIndex === -1) return null;
      
      server = serverPortPart.substring(1, closeBracketIndex); // 去掉方括号
      const portPart = serverPortPart.substring(closeBracketIndex + 1);
      port = portPart.startsWith(':') ? portPart.substring(1) : '';
    } else {
      // IPv4地址或域名，使用最后一个冒号分割
      const lastColonIndex = serverPortPart.lastIndexOf(':');
      if (lastColonIndex === -1) return null;
      
      server = serverPortPart.substring(0, lastColonIndex);
      port = serverPortPart.substring(lastColonIndex + 1);
    }
    
    if (!server || !port) return null;
    
    let method, password;
    const methodPassBase64 = prefixRemoved.substring(0, atIndex);
    try {
      [method, password] = safeBase64Decode(methodPassBase64).split(':');
    } catch {
      [method, password] = safeDecodeURIComponent(methodPassBase64).split(':');
    }
    
    if (!method || !password) return null;
    
    const nodeName = name ? decodeURIComponent(name) : '未命名节点';
    return `${nodeName} = ss, ${server}, ${port}, encrypt-method=${method}, password=${password}`;
  } catch {
    return null;
  }
}

// 解析Vmess链接为Surge格式
function parseVmessLink(vmessLink) {
  if (!vmessLink.startsWith(NODE_TYPES.VMESS)) return null;
  
  try {
    const config = JSON.parse(safeBase64Decode(vmessLink.substring(8)));
    if (!config.add || !config.port || !config.id) return null;
    
    // 正确处理UTF-8编码的中文字符
    const name = config.ps ? safeUtf8Decode(config.ps) : '未命名节点';
    const configParts = [
      `${name} = vmess`,
      config.add,
      config.port,
      `username=${config.id}`,
      'vmess-aead=true',
      `tls=${config.tls === 'tls'}`,
      `sni=${config.add}`,
      'skip-cert-verify=true',
      'tfo=false'
    ];

    if (config.tls === 'tls' && config.alpn) {
      configParts.push(`alpn=${config.alpn.replace(/,/g, ':')}`);
    }

    if (config.net === 'ws') {
      configParts.push('ws=true');
      if (config.path) configParts.push(`ws-path=${config.path}`);
      configParts.push(`ws-headers=Host:${config.host || config.add}`);
    }

    return configParts.join(', ');
  } catch {
    return null;
  }
}

// 解析Trojan链接为Surge格式
function parseTrojanLink(trojanLink) {
  if (!trojanLink.startsWith(NODE_TYPES.TROJAN)) return null;
  
  try {
    const url = new URL(trojanLink);
    if (!url.hostname || !url.port || !url.username) return null;
    
    const params = new URLSearchParams(url.search);
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    
    const configParts = [
      `${nodeName} = trojan`,
      url.hostname,
      url.port,
      `password=${url.username}`,
      'tls=true',
      `sni=${url.hostname}`,
      'skip-cert-verify=true',
      'tfo=false'
    ];

    const alpn = params.get('alpn');
    if (alpn) {
      configParts.push(`alpn=${safeDecodeURIComponent(alpn).replace(/,/g, ':')}`);
    }

    if (params.get('type') === 'ws') {
      configParts.push('ws=true');
      const path = params.get('path');
      if (path) {
        configParts.push(`ws-path=${safeDecodeURIComponent(path)}`);
      }
      const host = params.get('host');
      configParts.push(`ws-headers=Host:${host ? safeDecodeURIComponent(host) : url.hostname}`);
    }

    return configParts.join(', ');
  } catch {
    return null;
  }
}

// 解析SOCKS链接为Surge格式
function parseSocksLink(socksLink) {
  if (!socksLink.startsWith(NODE_TYPES.SOCKS)) return null;
  
  try {
    // 处理标准格式：socks://username:password@server:port#name
    // 或者 socks://base64encoded@server:port#name
    const url = new URL(socksLink);
    if (!url.hostname || !url.port) return null;
    
    // 提取节点名称
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    
    // 处理认证信息
    let username = '', password = '';
    
    // 专门处理 socks://base64auth@server:port 这样的格式
    if (url.username) {
      // 首先对username进行URL解码
      let decodedUsername = safeDecodeURIComponent(url.username);
      
      // 特殊处理 dXNlcm5hbWUxMjM6cGFzc3dvcmQxMjM= 这样的Base64编码认证信息
      try {
        // 尝试Base64解码
        const decoded = safeBase64Decode(decodedUsername);
        if (decoded.includes(':')) {
          // 成功解码为 username:password 格式
          const parts = decoded.split(':');
          if (parts.length >= 2) {
            username = parts[0];
            password = parts[1];
          } else {
            username = decodedUsername;
          }
        } else {
          // 不是预期的格式，使用原始值
          username = decodedUsername;
          if (url.password) {
            password = safeDecodeURIComponent(url.password);
          }
        }
      } catch (e) {
        username = decodedUsername;
        if (url.password) {
          password = safeDecodeURIComponent(url.password);
        }
      }
    }
    
    // 构建Surge格式
    const configParts = [
      nodeName + " = socks5",
      url.hostname,
      url.port
    ];
    
    // 如果有用户名密码，添加到配置中
    if (username) configParts.push(username);
    if (password) configParts.push(password);
    
    return configParts.join(', ');
  } catch (error) {
    return null;
  }
}

// 添加更新订阅信息的函数
async function handleUpdateSubscriptionInfo(env, path, data) {
  const name = data.name?.trim();
  const newPath = data.path?.trim();

  // 基本验证
  if (!name) {
    return createErrorResponse('订阅名称不能为空', 400);
  }
  
  if (!validateSubscriptionPath(newPath)) {
    return createErrorResponse('无效的订阅路径格式', 400);
  }

  try {
    // 如果路径被修改，检查新路径是否已存在
    if (newPath !== path) {
      const { results } = await env.DB.prepare(`
        SELECT 1 FROM subscriptions WHERE path = ? LIMIT 1
      `).bind(newPath).all();
      
      if (results.length > 0) {
        return createErrorResponse('该路径已被使用', 400);
      }
    }

    // 使用事务确保数据一致性
    const statements = [
      env.DB.prepare(
        "UPDATE subscriptions SET name = ?, path = ? WHERE path = ?"
      ).bind(name, newPath, path),
      env.DB.prepare(
        "SELECT id, name, path FROM subscriptions WHERE path = ?"
      ).bind(newPath)
    ];

    const [updateResult, { results }] = await env.DB.batch(statements);
    
    if (!results?.[0]) {
      return createErrorResponse('更新失败：找不到订阅', 404);
    }

    return createSuccessResponse(results[0], '订阅信息已更新');
  } catch (error) {
    return createErrorResponse('更新订阅信息失败: ' + error.message);
  }
}

// 添加删除订阅的处理函数
async function handleDeleteSubscription(env, path) {
  // 使用事务确保数据一致性
  const statements = [
    // 首先删除该订阅下的所有节点
    env.DB.prepare(
      "DELETE FROM nodes WHERE subscription_id IN (SELECT id FROM subscriptions WHERE path = ?)"
    ).bind(path),
    
    // 然后删除订阅
    env.DB.prepare(
      "DELETE FROM subscriptions WHERE path = ?"
    ).bind(path)
  ];
  
  // 执行事务
  await env.DB.batch(statements);
  
  return createSuccessResponse(null, '订阅已删除');
}

// 添加更新节点的处理函数
async function handleUpdateNode(request, env, subscriptionPath, nodeId) {
  const nodeData = await request.json();
  
  // 获取订阅ID
  const { results: subResults } = await env.DB.prepare(
    "SELECT id FROM subscriptions WHERE path = ?"
  ).bind(subscriptionPath).all();
  
  if (!subResults?.length) {
    return createErrorResponse('订阅不存在', 404);
  }
  
  const subscriptionId = subResults[0].id;
  let originalLink = nodeData.content.replace(/[\r\n\s]+$/, '');

  // 尝试base64解码
  try {
    const decodedContent = safeBase64Decode(originalLink);
    if (Object.values(NODE_TYPES).some(prefix => 
      decodedContent.startsWith(prefix) && prefix !== NODE_TYPES.SNELL)) {
      originalLink = decodedContent.replace(/[\r\n\s]+$/, '');
    }
  } catch (e) {} // 不是base64格式，继续使用原始内容

  // 使用通用的节点名称提取函数
  const nodeName = extractNodeName(originalLink);

  // 更新节点内容和名称
  await env.DB.prepare(`
    UPDATE nodes 
    SET original_link = ?, name = ? 
    WHERE id = ? AND subscription_id = ?
  `).bind(originalLink, nodeName || '未命名节点', nodeId, subscriptionId).run();

  return createSuccessResponse(null, '节点更新成功');
}

// 将订阅内容转换为surge格式
function convertToSurge(content) {
  if (!content?.trim()) return '';
  
  // 使用Map来映射节点类型和处理函数，提高性能
  const nodeParserMap = new Map([
    [NODE_TYPES.SS, parseSIP002Format],
    [NODE_TYPES.VMESS, parseVmessLink],
    [NODE_TYPES.TROJAN, parseTrojanLink],
    [NODE_TYPES.SOCKS, parseSocksLink],
    [NODE_TYPES.HYSTERIA2, parseHysteria2ToSurge],
    [NODE_TYPES.TUIC, parseTuicToSurge]
  ]);
  
  return content
    .split(/\r?\n/)
    .map(line => {
      const trimmedLine = line.trim();
      if (!trimmedLine) return null;
      
      // 如果已经是snell格式,格式化并返回
      if (trimmedLine.includes(NODE_TYPES.SNELL)) {
        return formatSnellConfig(trimmedLine);
      }
      
      // 跳过 VLESS 节点
      if (trimmedLine.toLowerCase().startsWith(NODE_TYPES.VLESS)) {
        return null;
      }
      
      // 检查是否有匹配的解析器
      for (const [prefix, parser] of nodeParserMap.entries()) {
        if (trimmedLine.startsWith(prefix)) {
          return parser(trimmedLine);
        }
      }
      
      return null;
    })
    .filter(Boolean)
    .join('\n');
}

// 格式化snell配置
function formatSnellConfig(snellConfig) {
  if (!snellConfig) return null;
  
  // 分割配置字符串，保持格式一致
  const parts = snellConfig.split(',').map(part => part.trim());
  return parts.join(', ');
}

// 安全的URL解码辅助函数
function safeDecodeURIComponent(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

// 安全的Base64编码辅助函数，支持Unicode字符
function safeBase64Encode(str) {
  try {
    return btoa(unescape(encodeURIComponent(str)));
  } catch (e) {
    return str;
  }
}

// 安全的Base64解码辅助函数
function safeBase64Decode(str) {
  try {
    // 方法1：使用atob解码，然后正确处理UTF-8编码
    const decoded = atob(str);
    // 将解码结果转换为UTF-8字符串
    const bytes = [];
    for (let i = 0; i < decoded.length; i++) {
      bytes.push(decoded.charCodeAt(i));
    }
    // 使用TextDecoder正确解码UTF-8字符
    if (typeof TextDecoder !== 'undefined') {
      const decoder = new TextDecoder('utf-8');
      return decoder.decode(new Uint8Array(bytes));
    } else {
      // 如果没有TextDecoder，使用escape + decodeURIComponent
      let utf8String = '';
      for (let i = 0; i < bytes.length; i++) {
        utf8String += String.fromCharCode(bytes[i]);
      }
      return decodeURIComponent(escape(utf8String));
    }
  } catch (e) {
    try {
      // 方法2：直接使用atob，可能适用于简单ASCII字符
      return atob(str);
    } catch (e2) {
      // 如果Base64解码失败，返回原字符串
      return str;
    }
  }
}

// 安全的UTF-8字符串解码函数
function safeUtf8Decode(str) {
  if (!str) return str;
  
  try {
    // 方法1：使用escape + decodeURIComponent
    return decodeURIComponent(escape(str));
  } catch (e1) {
    try {
      // 方法2：直接使用decodeURIComponent
      return decodeURIComponent(str);
    } catch (e2) {
      try {
        // 方法3：使用TextDecoder（如果支持）
        if (typeof TextDecoder !== 'undefined') {
          const encoder = new TextEncoder();
          const decoder = new TextDecoder('utf-8');
          return decoder.decode(encoder.encode(str));
        }
      } catch (e3) {
        // 如果所有方法都失败，返回原始字符串
        return str;
      }
      return str;
    }
  }
}

// 过滤掉snell节点的函数
function filterSnellNodes(content) {
  if (!content?.trim()) return '';
  
  return content
    .split(/\r?\n/)
    .filter(line => {
      const trimmedLine = line.trim();
      if (!trimmedLine) return false;
      
      // 过滤掉snell节点
      return !trimmedLine.includes(NODE_TYPES.SNELL);
    })
    .join('\n');
}

// 将订阅内容转换为 Clash 格式
function convertToClash(content) {
  if (!content?.trim()) {
    return generateEmptyClashConfig();
  }
  
  const nodes = content
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .map(parseNodeToClash)
    .filter(Boolean);
  
  return generateClashConfig(nodes);
}

// 解析单个节点为 Clash 格式
function parseNodeToClash(nodeLink) {
  if (!nodeLink) return null;
  
  const lowerLink = nodeLink.toLowerCase();
  
  // 跳过 snell 节点，Clash 不支持
  if (nodeLink.includes(NODE_TYPES.SNELL)) {
    return null;
  }
  
  // 解析 SS 节点
  if (lowerLink.startsWith(NODE_TYPES.SS)) {
    return parseSSToClash(nodeLink);
  }
  
  // 解析 VMess 节点
  if (lowerLink.startsWith(NODE_TYPES.VMESS)) {
    return parseVmessToClash(nodeLink);
  }
  
  // 解析 Trojan 节点
  if (lowerLink.startsWith(NODE_TYPES.TROJAN)) {
    return parseTrojanToClash(nodeLink);
  }
  
  // 解析 VLESS 节点
  if (lowerLink.startsWith(NODE_TYPES.VLESS)) {
    return parseVlessToClash(nodeLink);
  }
  
  // 解析 SOCKS 节点
  if (lowerLink.startsWith(NODE_TYPES.SOCKS)) {
    return parseSocksToClash(nodeLink);
  }
  
  // 解析 Hysteria2 节点
  if (lowerLink.startsWith(NODE_TYPES.HYSTERIA2)) {
    return parseHysteria2ToClash(nodeLink);
  }
  
  // 解析 TUIC 节点
  if (lowerLink.startsWith(NODE_TYPES.TUIC)) {
    return parseTuicToClash(nodeLink);
  }
  
  return null;
}

// 解析 SS 节点为 Clash 格式
function parseSSToClash(ssLink) {
  try {
    const [base, name = ''] = ssLink.split('#');
    if (!base.startsWith(NODE_TYPES.SS)) return null;
    
    const prefixRemoved = base.substring(5);
    const atIndex = prefixRemoved.indexOf('@');
    if (atIndex === -1) return null;
    
    // 正确解析服务器地址和端口，支持IPv6
    const serverPortPart = prefixRemoved.substring(atIndex + 1);
    let server, port;
    
    // 检查是否是IPv6地址（用方括号包围）
    if (serverPortPart.startsWith('[')) {
      const closeBracketIndex = serverPortPart.indexOf(']');
      if (closeBracketIndex === -1) return null;
      
      server = serverPortPart.substring(1, closeBracketIndex); // 去掉方括号
      const portPart = serverPortPart.substring(closeBracketIndex + 1);
      port = portPart.startsWith(':') ? portPart.substring(1) : '';
    } else {
      // IPv4地址或域名，使用最后一个冒号分割
      const lastColonIndex = serverPortPart.lastIndexOf(':');
      if (lastColonIndex === -1) return null;
      
      server = serverPortPart.substring(0, lastColonIndex);
      port = serverPortPart.substring(lastColonIndex + 1);
    }
    
    if (!server || !port) return null;
    
    let method, password;
    const methodPassBase64 = prefixRemoved.substring(0, atIndex);
    try {
      [method, password] = safeBase64Decode(methodPassBase64).split(':');
    } catch {
      [method, password] = safeDecodeURIComponent(methodPassBase64).split(':');
    }
    
    if (!method || !password) return null;
    
    return {
      name: name ? decodeURIComponent(name) : '未命名节点',
      type: 'ss',
      server: server,
      port: parseInt(port),
      cipher: method,
      password: password
    };
  } catch {
    return null;
  }
}

// 解析 VMess 节点为 Clash 格式
function parseVmessToClash(vmessLink) {
  if (!vmessLink.startsWith(NODE_TYPES.VMESS)) return null;
  
  try {
    const config = JSON.parse(safeBase64Decode(vmessLink.substring(8)));
    if (!config.add || !config.port || !config.id) return null;
    
    const node = {
      name: config.ps ? safeUtf8Decode(config.ps) : '未命名节点',
      type: 'vmess',
      server: config.add,
      port: parseInt(config.port),
      uuid: config.id,
      alterId: parseInt(config.aid) || 0,
      cipher: 'auto',
      tls: config.tls === 'tls'
    };
    
    // 添加网络类型配置
    if (config.net === 'ws') {
      node.network = 'ws';
      if (config.path) {
        node['ws-opts'] = {
          path: config.path,
          headers: {
            Host: config.host || config.add
          }
        };
      }
    } else if (config.net === 'grpc') {
      node.network = 'grpc';
      if (config.path) {
        node['grpc-opts'] = {
          'grpc-service-name': config.path
        };
      }
    }
    
    // TLS 配置
    if (config.tls === 'tls') {
      node['skip-cert-verify'] = true;
      if (config.sni) {
        node.servername = config.sni;
      }
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 Trojan 节点为 Clash 格式
function parseTrojanToClash(trojanLink) {
  if (!trojanLink.startsWith(NODE_TYPES.TROJAN)) return null;
  
  try {
    const url = new URL(trojanLink);
    if (!url.hostname || !url.port || !url.username) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'trojan',
      server: url.hostname,
      port: parseInt(url.port),
      password: url.username,
      'skip-cert-verify': true
    };
    
    // 添加网络类型配置
    if (params.get('type') === 'ws') {
      node.network = 'ws';
      const path = params.get('path');
      const host = params.get('host');
      if (path || host) {
        node['ws-opts'] = {};
        if (path) node['ws-opts'].path = safeDecodeURIComponent(path);
        if (host) {
          node['ws-opts'].headers = { Host: safeDecodeURIComponent(host) };
        }
      }
    } else if (params.get('type') === 'grpc') {
      node.network = 'grpc';
      const serviceName = params.get('serviceName') || params.get('path');
      if (serviceName) {
        node['grpc-opts'] = {
          'grpc-service-name': safeDecodeURIComponent(serviceName)
        };
      }
    }
    
    // SNI 配置
    const sni = params.get('sni');
    if (sni) {
      node.sni = safeDecodeURIComponent(sni);
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 VLESS 节点为 Clash 格式
function parseVlessToClash(vlessLink) {
  if (!vlessLink.startsWith(NODE_TYPES.VLESS)) return null;
  
  try {
    const url = new URL(vlessLink);
    if (!url.hostname || !url.port || !url.username) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'vless',
      server: url.hostname,
      port: parseInt(url.port),
      uuid: url.username,
      tls: params.get('security') === 'tls' || params.get('security') === 'reality',
      'client-fingerprint': 'chrome',
      tfo: false,
      'skip-cert-verify': false
    };
    
    // 添加 flow 参数
    const flow = params.get('flow');
    if (flow) {
      node.flow = flow;
    }
    
    // Reality 配置
    if (params.get('security') === 'reality') {
      const publicKey = params.get('pbk');
      const shortId = params.get('sid');
      if (publicKey || shortId) {
        node['reality-opts'] = {};
        if (publicKey) node['reality-opts']['public-key'] = publicKey;
        if (shortId) node['reality-opts']['short-id'] = shortId;
      }
    }
    
    // 添加网络类型配置
    const type = params.get('type');
    if (type === 'ws') {
      node.network = 'ws';
      const path = params.get('path');
      const host = params.get('host');
      if (path || host) {
        node['ws-opts'] = {};
        if (path) node['ws-opts'].path = safeDecodeURIComponent(path);
        if (host) {
          node['ws-opts'].headers = { Host: safeDecodeURIComponent(host) };
        }
      }
    } else if (type === 'grpc') {
      node.network = 'grpc';
      const serviceName = params.get('serviceName') || params.get('path');
      if (serviceName) {
        node['grpc-opts'] = {
          'grpc-service-name': safeDecodeURIComponent(serviceName)
        };
      }
    } else if (type === 'tcp') {
      node.network = 'tcp';
    } else {
      // 默认设置为 tcp
      node.network = 'tcp';
    }
    
    // SNI 配置
    const sni = params.get('sni');
    if (sni) {
      node.servername = safeDecodeURIComponent(sni);
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 SOCKS 节点为 Clash 格式
function parseSocksToClash(socksLink) {
  if (!socksLink.startsWith(NODE_TYPES.SOCKS)) return null;
  
  try {
    const url = new URL(socksLink);
    if (!url.hostname || !url.port) return null;
    
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'socks5',
      server: url.hostname,
      port: parseInt(url.port)
    };
    
    // 处理认证信息
    if (url.username) {
      let username = '', password = '';
      let decodedUsername = safeDecodeURIComponent(url.username);
      
      try {
        const decoded = safeBase64Decode(decodedUsername);
        if (decoded.includes(':')) {
          const parts = decoded.split(':');
          if (parts.length >= 2) {
            username = parts[0];
            password = parts[1];
          }
        } else {
          username = decodedUsername;
          if (url.password) {
            password = safeDecodeURIComponent(url.password);
          }
        }
      } catch (e) {
        username = decodedUsername;
        if (url.password) {
          password = safeDecodeURIComponent(url.password);
        }
      }
      
      if (username) node.username = username;
      if (password) node.password = password;
    }
    
    return node;
  } catch {
    return null;
  }
}

// 生成 Clash 配置文件
function generateClashConfig(proxies) {
  const proxyNames = proxies.map(proxy => proxy.name);
  
  const config = {
    // 用于下载订阅时指定UA
    'global-ua': 'clash',
    
    // 全局配置
    mode: 'rule',
    'mixed-port': 7890,
    'allow-lan': true,
    
    // 控制面板
    'external-controller': '0.0.0.0:9090',
    
    
    // 如果有代理节点，则包含代理节点配置
    proxies: proxies.length > 0 ? proxies : [],
    
    // 策略组
    'proxy-groups': [
      {
        name: '节点选择',
        type: 'select',
        proxies: ['DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png'
      },
      {
        name: '媒体服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png'
      },
      {
        name: '微软服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Microsoft.png'
      },
      {
        name: '苹果服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple.png'
      },
      {
        name: 'CDN服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/OneDrive.png'
      },
      {
        name: 'AI服务',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png'
      },
      {
        name: 'Telegram',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram.png'
      },
      {
        name: 'Speedtest',
        type: 'select',
        proxies: ['节点选择', 'DIRECT'].concat(proxyNames),
        icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Speedtest.png'
      },
    ],
    
    // 分流规则
    rules: [
      'RULE-SET,reject_non_ip,REJECT',
      'RULE-SET,reject_domainset,REJECT',
      'RULE-SET,reject_extra_domainset,REJECT',
      'RULE-SET,reject_non_ip_drop,REJECT-DROP',
      'RULE-SET,reject_non_ip_no_drop,REJECT',
      
      
      // 域名类规则
      'RULE-SET,speedtest,Speedtest',
      'RULE-SET,telegram_non_ip,Telegram',
      'RULE-SET,apple_cdn,DIRECT',
      'RULE-SET,apple_cn_non_ip,DIRECT',
      'RULE-SET,microsoft_cdn_non_ip,DIRECT',
      'RULE-SET,apple_services,苹果服务',
      'RULE-SET,microsoft_non_ip,微软服务',
      'RULE-SET,download_domainset,CDN服务',
      'RULE-SET,download_non_ip,CDN服务',
      'RULE-SET,cdn_domainset,CDN服务',
      'RULE-SET,cdn_non_ip,CDN服务',
      'RULE-SET,stream_non_ip,媒体服务',
      'RULE-SET,ai_non_ip,AI服务',
      'RULE-SET,global_non_ip,节点选择',
      'RULE-SET,domestic_non_ip,DIRECT',
      'RULE-SET,direct_non_ip,DIRECT',
      'RULE-SET,lan_non_ip,DIRECT',
      'GEOSITE,CN,DIRECT',
      
      // IP 类规则
      'RULE-SET,reject_ip,REJECT',
      'RULE-SET,telegram_ip,Telegram',
      'RULE-SET,stream_ip,媒体服务',
      'RULE-SET,lan_ip,DIRECT',
      'RULE-SET,domestic_ip,DIRECT',
      'RULE-SET,china_ip,DIRECT',
      'GEOIP,LAN,DIRECT',
      'GEOIP,CN,DIRECT',
      
      // 兜底规则
      'MATCH,节点选择'
    ],
    
    // 规则提供者
    'rule-providers': {
      reject_non_ip_no_drop: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/reject-no-drop.txt',
        path: './rule_set/sukkaw_ruleset/reject_non_ip_no_drop.txt'
      },
      reject_non_ip_drop: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/reject-drop.txt',
        path: './rule_set/sukkaw_ruleset/reject_non_ip_drop.txt'
      },
      reject_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/reject.txt',
        path: './rule_set/sukkaw_ruleset/reject_non_ip.txt'
      },
      reject_domainset: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/domainset/reject.txt',
        path: './rule_set/sukkaw_ruleset/reject_domainset.txt'
      },
      reject_extra_domainset: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/domainset/reject_extra.txt',
        path: './sukkaw_ruleset/reject_domainset_extra.txt'
      },
      reject_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/ip/reject.txt',
        path: './rule_set/sukkaw_ruleset/reject_ip.txt'
      },
      speedtest: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: 'Speedtest',
        url: 'https://ruleset.skk.moe/Clash/domainset/speedtest.txt',
        path: './rule_set/sukkaw_ruleset/speedtest.txt'
      },
      cdn_domainset: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/domainset/cdn.txt',
        path: './rule_set/sukkaw_ruleset/cdn_domainset.txt'
      },
      cdn_non_ip: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/cdn.txt',
        path: './rule_set/sukkaw_ruleset/cdn_non_ip.txt'
      },
      stream_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/stream.txt',
        path: './rule_set/sukkaw_ruleset/stream_non_ip.txt'
      },
      stream_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/ip/stream.txt',
        path: './rule_set/sukkaw_ruleset/stream_ip.txt'
      },
      ai_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/ai.txt',
        path: './rule_set/sukkaw_ruleset/ai_non_ip.txt'
      },
      telegram_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/telegram.txt',
        path: './rule_set/sukkaw_ruleset/telegram_non_ip.txt'
      },
      telegram_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/ip/telegram.txt',
        path: './rule_set/sukkaw_ruleset/telegram_ip.txt'
      },
      apple_cdn: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/domainset/apple_cdn.txt',
        path: './rule_set/sukkaw_ruleset/apple_cdn.txt'
      },
      apple_services: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/apple_services.txt',
        path: './rule_set/sukkaw_ruleset/apple_services.txt'
      },
      apple_cn_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/apple_cn.txt',
        path: './rule_set/sukkaw_ruleset/apple_cn_non_ip.txt'
      },
      microsoft_cdn_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/microsoft_cdn.txt',
        path: './rule_set/sukkaw_ruleset/microsoft_cdn_non_ip.txt'
      },
      microsoft_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/microsoft.txt',
        path: './rule_set/sukkaw_ruleset/microsoft_non_ip.txt'
      },
      download_domainset: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/domainset/download.txt',
        path: './rule_set/sukkaw_ruleset/download_domainset.txt'
      },
      download_non_ip: {
        type: 'http',
        behavior: 'domain',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/download.txt',
        path: './rule_set/sukkaw_ruleset/download_non_ip.txt'
      },
      lan_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/lan.txt',
        path: './rule_set/sukkaw_ruleset/lan_non_ip.txt'
      },
      lan_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/ip/lan.txt',
        path: './rule_set/sukkaw_ruleset/lan_ip.txt'
      },
      domestic_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/domestic.txt',
        path: './rule_set/sukkaw_ruleset/domestic_non_ip.txt'
      },
      direct_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/direct.txt',
        path: './rule_set/sukkaw_ruleset/direct_non_ip.txt'
      },
      global_non_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/non_ip/global.txt',
        path: './rule_set/sukkaw_ruleset/global_non_ip.txt'
      },
      domestic_ip: {
        type: 'http',
        behavior: 'classical',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/ip/domestic.txt',
        path: './rule_set/sukkaw_ruleset/domestic_ip.txt'
      },
      china_ip: {
        type: 'http',
        behavior: 'ipcidr',
        interval: 43200,
        format: 'text',
        proxy: '节点选择',
        url: 'https://ruleset.skk.moe/Clash/ip/china_ip.txt',
        path: './rule_set/sukkaw_ruleset/china_ip.txt'
      }
    }
  };
  
  return `# Clash 配置文件 - Sub-Hub 自动生成
# 生成时间: ${new Date().toISOString()}

${convertToYaml(config)}`;
}

// 生成空的 Clash 配置
function generateEmptyClashConfig() {
  return generateClashConfig([]);
}

// 简化的对象转 YAML 函数，针对 Clash 配置优化
function convertToYaml(obj, indent = 0) {
  const spaces = '  '.repeat(indent);
  let yaml = '';
  
  for (const [key, value] of Object.entries(obj)) {
    // 处理键名，只对真正需要的情况加引号
    let yamlKey = key;
    if (key.includes(' ') || key.includes('@') || key.includes('&') || 
        key.includes('*') || key.includes('?') || key.includes('>') || 
        key.includes('<') || key.includes('!') || key.includes('%') || 
        key.includes('^') || key.includes('`') || /^\d/.test(key) || 
        key === '' || /^(true|false|null|yes|no|on|off)$/i.test(key)) {
      yamlKey = `"${key.replace(/"/g, '\\"')}"`;
    }
    
    if (value === null || value === undefined) {
      yaml += `${spaces}${yamlKey}: null\n`;
    } else if (typeof value === 'boolean') {
      yaml += `${spaces}${yamlKey}: ${value}\n`;
    } else if (typeof value === 'number') {
      yaml += `${spaces}${yamlKey}: ${value}\n`;
    } else if (typeof value === 'string') {
      // 对字符串值更宽松的引号判断，主要针对真正会导致 YAML 解析问题的字符
      const needsQuotes = value.includes(':') || value.includes('#') || 
                         value.includes('"') || value.includes('\n') ||
                         value.includes('&') || value.includes('*') ||
                         value.includes('[') || value.includes(']') ||
                         value.includes('{') || value.includes('}') ||
                         value.includes('@') || value.includes('`') ||
                         /^\s/.test(value) || /\s$/.test(value) || 
                         value === '' || /^(true|false|null|yes|no|on|off)$/i.test(value) ||
                         (/^\d+$/.test(value) && value.length > 1) || 
                         (/^\d+\.\d+$/.test(value) && value.length > 1);
      
      if (needsQuotes) {
        const escapedValue = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        yaml += `${spaces}${yamlKey}: "${escapedValue}"\n`;
      } else {
        yaml += `${spaces}${yamlKey}: ${value}\n`;
      }
    } else if (Array.isArray(value)) {
      if (value.length === 0) {
        yaml += `${spaces}${yamlKey}: []\n`;
      } else {
        yaml += `${spaces}${yamlKey}:\n`;
        for (const item of value) {
          if (typeof item === 'object' && item !== null) {
            yaml += `${spaces}  -\n`;
            const itemYaml = convertToYaml(item, 0);
            yaml += itemYaml.split('\n').map(line => 
              line.trim() ? `${spaces}    ${line}` : ''
            ).filter(line => line).join('\n') + '\n';
          } else if (typeof item === 'string') {
            // 对数组中的字符串项（如节点名称）更宽松的引号判断
            const needsQuotes = item.includes(':') || item.includes('#') || 
                               item.includes('"') || item.includes('\n') ||
                               item.includes('&') || item.includes('*') ||
                               item.includes('[') || item.includes(']') ||
                               item.includes('{') || item.includes('}') ||
                               item.includes('@') || item.includes('`') ||
                               /^\s/.test(item) || /\s$/.test(item) || 
                               item === '' || /^(true|false|null|yes|no|on|off)$/i.test(item) ||
                               (/^\d+$/.test(item) && item.length > 1) || 
                               (/^\d+\.\d+$/.test(item) && item.length > 1);
            
            if (needsQuotes) {
              const escapedItem = item.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
              yaml += `${spaces}  - "${escapedItem}"\n`;
            } else {
              yaml += `${spaces}  - ${item}\n`;
            }
          } else {
            yaml += `${spaces}  - ${item}\n`;
          }
        }
      }
    } else if (typeof value === 'object' && value !== null) {
      yaml += `${spaces}${yamlKey}:\n`;
      yaml += convertToYaml(value, indent + 1);
    }
  }
  
  return yaml;
}

// 解析 Hysteria2 节点为 Clash 格式
function parseHysteria2ToClash(hysteria2Link) {
  if (!hysteria2Link.startsWith(NODE_TYPES.HYSTERIA2)) return null;
  
  try {
    const url = new URL(hysteria2Link);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'hysteria2',
      server: url.hostname,
      port: parseInt(url.port),
      password: url.username || params.get('password') || '',
      'skip-cert-verify': true
    };
    
    // 上传和下载速度配置
    const upMbps = params.get('upmbps') || params.get('up');
    const downMbps = params.get('downmbps') || params.get('down');
    if (upMbps) node.up = upMbps;
    if (downMbps) node.down = downMbps;
    
    // SNI 配置
    const sni = params.get('sni');
    if (sni) {
      node.sni = safeDecodeURIComponent(sni);
    }
    
    // ALPN 配置
    const alpn = params.get('alpn');
    if (alpn) {
      node.alpn = alpn.split(',').map(s => s.trim());
    }
    
    // 混淆配置
    const obfs = params.get('obfs');
    if (obfs) {
      node.obfs = safeDecodeURIComponent(obfs);
      const obfsPassword = params.get('obfs-password');
      if (obfsPassword) {
        node['obfs-password'] = safeDecodeURIComponent(obfsPassword);
      }
    }
    
    // 拥塞控制算法
    const cc = params.get('cc');
    if (cc) {
      node.cc = cc;
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 TUIC 节点为 Clash 格式
function parseTuicToClash(tuicLink) {
  if (!tuicLink.startsWith(NODE_TYPES.TUIC)) return null;
  
  try {
    const url = new URL(tuicLink);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const node = {
      name: url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点',
      type: 'tuic',
      server: url.hostname,
      port: parseInt(url.port),
      uuid: url.username || params.get('uuid') || '',
      password: url.password || params.get('password') || '',
      'skip-cert-verify': true
    };
    
    // TUIC 版本
    const version = params.get('version') || params.get('v');
    if (version) {
      node.version = parseInt(version);
    }
    
    // SNI 配置
    const sni = params.get('sni');
    if (sni) {
      node.sni = safeDecodeURIComponent(sni);
    }
    
    // ALPN 配置
    const alpn = params.get('alpn');
    if (alpn) {
      node.alpn = alpn.split(',').map(s => s.trim());
    }
    
    // UDP Relay 模式
    const udpRelayMode = params.get('udp_relay_mode') || params.get('udp-relay-mode');
    if (udpRelayMode) {
      node['udp-relay-mode'] = udpRelayMode;
    }
    
    // 拥塞控制算法
    const cc = params.get('congestion_control') || params.get('cc');
    if (cc) {
      node['congestion-control'] = cc;
    }
    
    // 禁用 SNI
    const disableSni = params.get('disable_sni');
    if (disableSni === 'true' || disableSni === '1') {
      node['disable-sni'] = true;
    }
    
    // 减少 RTT
    const reduceRtt = params.get('reduce_rtt');
    if (reduceRtt === 'true' || reduceRtt === '1') {
      node['reduce-rtt'] = true;
    }
    
    return node;
  } catch {
    return null;
  }
}

// 解析 Hysteria2 链接为 Surge 格式
function parseHysteria2ToSurge(hysteria2Link) {
  if (!hysteria2Link.startsWith(NODE_TYPES.HYSTERIA2)) return null;
  
  try {
    const url = new URL(hysteria2Link);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    const password = url.username || params.get('password') || '';
    
    // 构建 Surge 格式的 Hysteria2 配置
    const configParts = [
      `${nodeName} = hysteria2`,
      url.hostname,
      url.port,
      `password=${password}`
    ];
    
    // 添加可选参数
    const upMbps = params.get('upmbps') || params.get('up');
    const downMbps = params.get('downmbps') || params.get('down');
    if (upMbps) configParts.push(`up=${upMbps}`);
    if (downMbps) configParts.push(`down=${downMbps}`);
    
    const sni = params.get('sni');
    if (sni) configParts.push(`sni=${safeDecodeURIComponent(sni)}`);
    
    const alpn = params.get('alpn');
    if (alpn) configParts.push(`alpn=${alpn}`);
    
    const obfs = params.get('obfs');
    if (obfs) {
      configParts.push(`obfs=${safeDecodeURIComponent(obfs)}`);
      const obfsPassword = params.get('obfs-password');
      if (obfsPassword) {
        configParts.push(`obfs-password=${safeDecodeURIComponent(obfsPassword)}`);
      }
    }
    
    const cc = params.get('cc');
    if (cc) configParts.push(`cc=${cc}`);
    
    // 默认跳过证书验证
    configParts.push('skip-cert-verify=true');
    
    return configParts.join(', ');
  } catch (error) {
    return null;
  }
}

// 解析 TUIC 链接为 Surge 格式
function parseTuicToSurge(tuicLink) {
  if (!tuicLink.startsWith(NODE_TYPES.TUIC)) return null;
  
  try {
    const url = new URL(tuicLink);
    if (!url.hostname || !url.port) return null;
    
    const params = new URLSearchParams(url.search);
    const nodeName = url.hash ? decodeURIComponent(url.hash.substring(1)) : '未命名节点';
    const uuid = url.username || params.get('uuid') || '';
    const password = url.password || params.get('password') || '';
    
    // 构建 Surge 格式的 TUIC 配置
    const configParts = [
      `${nodeName} = tuic`,
      url.hostname,
      url.port,
      `uuid=${uuid}`,
      `password=${password}`
    ];
    
    // TUIC 版本 - 如果没有指定版本，默认使用版本 5
    const version = params.get('version') || params.get('v') || '5';
    configParts.push(`version=${version}`);
    
    // SNI 配置 - 如果没有指定 SNI，使用服务器地址作为 SNI
    const sni = params.get('sni') || url.hostname;
    configParts.push(`sni=${safeDecodeURIComponent(sni)}`);
    
    const alpn = params.get('alpn');
    if (alpn) configParts.push(`alpn=${alpn}`);
    
    // 处理 allow_insecure 参数
    const allowInsecure = params.get('allow_insecure') || params.get('allowInsecure');
    if (allowInsecure === 'true' || allowInsecure === '1') {
      configParts.push('skip-cert-verify=true');
    } else {
      // 如果没有明确设置 allow_insecure，默认为 false
      configParts.push('skip-cert-verify=false');
    }
    
    const udpRelayMode = params.get('udp_relay_mode') || params.get('udp-relay-mode');
    if (udpRelayMode) configParts.push(`udp-relay-mode=${udpRelayMode}`);
    
    const cc = params.get('congestion_control') || params.get('congestion-control') || params.get('cc');
    if (cc) configParts.push(`congestion-control=${cc}`);
    
    const disableSni = params.get('disable_sni');
    if (disableSni === 'true' || disableSni === '1') {
      configParts.push('disable-sni=true');
    }
    
    const reduceRtt = params.get('reduce_rtt');
    if (reduceRtt === 'true' || reduceRtt === '1') {
      configParts.push('reduce-rtt=true');
    }
    
    return configParts.join(', ');
  } catch (error) {
    return null;
  }
}
