const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');

const config = require('./config');
const { initDB, User, SiteContent, BannedIP, ChatMessage, Feedback } = require('./database');
const qqAuth = require('./qqAuth');

const app = express();

// 获取客户端真实IP
function getClientIp(req) {
  // 优先从代理头获取（如果部署在反向代理后）
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    const ips = forwardedFor.split(',');
    return ips[0].trim();
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp;
  }
  // 从连接中获取
  let ip = req.connection.remoteAddress || req.socket.remoteAddress || '';
  // IPv6 localhost 转换为 IPv4
  if (ip === '::1' || ip === '::ffff:127.0.0.1') {
    ip = '127.0.0.1';
  }
  // 移除IPv6前缀
  if (ip.startsWith('::ffff:')) {
    ip = ip.slice(7);
  }
  return ip;
}

// 初始化数据库
initDB();

// 中间件配置
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session 配置
app.use(session({
  secret: config.server.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7天
  }
}));

// 全局中间件 - IP封禁检查（最优先）
app.use((req, res, next) => {
  // 管理后台的解除封禁操作不受IP封禁限制
  if (req.path.startsWith('/admin/') && req.method === 'POST') {
    return next();
  }
  
  const clientIp = getClientIp(req);
  const banned = BannedIP.isBanned(clientIp);
  
  if (banned) {
    res.status(403);
    return res.render('banned-ip', {
      title: '访问被禁止',
      ip: clientIp,
      reason: banned.reason,
      banned_at: banned.banned_at
    });
  }
  
  next();
});

// 全局中间件 - 将用户信息传到模板
app.use((req, res, next) => {
  // 获取所有页面（用于导航栏）
  const allPages = SiteContent.getAll().filter(p => p.page_name !== 'home');
  res.locals.sitePages = allPages;
  
  // 未登录访问控制：只允许访问首页、登录注册、反馈页和静态资源
  const publicPaths = [
    '/', '/login', '/register', '/mock-login', '/logout',
    '/feedback', '/feedback/submit'
  ];
  const isPublicPath = publicPaths.includes(req.path) || 
    req.path.startsWith('/auth/') ||
    req.path.startsWith('/css/') ||
    req.path.startsWith('/js/') ||
    req.path.startsWith('/uploads/') ||
    req.path.startsWith('/images/') ||
    req.path === '/favicon.ico';
  
  if (!req.session.userId && !isPublicPath) {
    return res.redirect('/login');
  }
  
  if (req.session.userId) {
    const user = User.findById(req.session.userId);
    if (user) {
      // 检查用户是否被封禁，如果被封禁则强制退出
      if (user.is_banned === 1 && !req.path.startsWith('/login') && req.path !== '/logout') {
        req.session.destroy();
        return res.redirect('/login?error=' + encodeURIComponent('账号已被注销，原因：' + (user.ban_reason || '违反网站规定')));
      }
      res.locals.currentUser = user;
      res.locals.isLoggedIn = true;
      res.locals.isAdmin = user.is_admin === 1;
      res.locals.justRegistered = req.session.justRegistered || false;
      // 清除刚注册的标志
      if (req.session.justRegistered) {
        req.session.justRegistered = false;
      }
    } else {
      req.session.destroy();
      res.locals.isLoggedIn = false;
      res.locals.isAdmin = false;
    }
  } else {
    res.locals.isLoggedIn = false;
    res.locals.isAdmin = false;
    res.locals.currentUser = null;
  }
  next();
});

// ==================== 路由 ====================

// 首页
app.get('/', (req, res) => {
  const content = SiteContent.getByPageName('home');
  res.render('index', {
    title: content ? content.title : '首页',
    content: content ? content.content : '<p>欢迎访问</p>'
  });
});

// 登录页面
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  
  const qqAuthUrl = qqAuth.getQQAuthUrl(state);
  
  res.render('login', {
    title: '登录',
    qqAuthUrl: qqAuthUrl,
    useRealQQLogin: config.useRealQQLogin,
    error: req.query.error,
    success: req.query.success
  });
});

// QQ号+密码登录
app.post('/auth/qq/login', (req, res) => {
  const { qq_number, password } = req.body;
  
  // 验证QQ号格式
  if (!qq_number || !/^\d{5,12}$/.test(qq_number)) {
    return res.redirect('/login?error=请输入有效的QQ号');
  }
  
  if (!password) {
    return res.redirect('/login?error=请输入密码');
  }
  
  try {
    // 查找用户
    const user = User.findByQQNumber(qq_number);
    
    if (!user) {
      return res.redirect('/login?error=该QQ号未注册，请先注册');
    }
    
    if (!user.password) {
      return res.redirect('/login?error=该账号未设置密码，请先找回或重置密码');
    }
    
    // 验证密码
    if (!User.verifyPassword(user.id, password)) {
      return res.redirect('/login?error=密码错误');
    }
    
    // 检查是否被封禁
    if (user.is_banned === 1) {
      const reason = user.ban_reason ? `，原因：${user.ban_reason}` : '';
      return res.redirect(`/login?error=${encodeURIComponent('账号已被注销' + reason)}`);
    }
    
    // 登录成功 - 记录登录IP
    const clientIp = getClientIp(req);
    User.updateLoginInfo(user.id, clientIp);
    req.session.userId = user.id;
    res.redirect('/');
  } catch (error) {
    console.error('登录失败:', error.message);
    res.redirect(`/login?error=${encodeURIComponent(error.message)}`);
  }
});

// 注册页面 - 第一步：输入QQ号
app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  
  res.render('register', {
    title: '注册账号',
    step: 1,
    qq_number: '',
    error: req.query.error
  });
});

// 注册 - 提交QQ号，进入第二步设置密码
app.post('/register', (req, res) => {
  const { qq_number } = req.body;
  
  if (!qq_number || !/^\d{5,12}$/.test(qq_number)) {
    return res.redirect('/register?error=请输入有效的QQ号');
  }
  
  // 检查QQ号是否已注册
  const existingUser = User.findByQQNumber(qq_number);
  if (existingUser) {
    return res.redirect('/login?error=该QQ号已注册，请直接登录');
  }
  
  // 将QQ号存入session，进入设置密码步骤
  req.session.registerQQ = qq_number;
  res.redirect('/register/password');
});

// 注册页面 - 第二步：设置密码
app.get('/register/password', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/');
  }
  
  if (!req.session.registerQQ) {
    return res.redirect('/register');
  }
  
  res.render('register', {
    title: '设置密码',
    step: 2,
    qq_number: req.session.registerQQ,
    error: req.query.error
  });
});

// 注册 - 设置密码，完成注册
app.post('/register/password', (req, res) => {
  const { password, confirm_password } = req.body;
  const qq_number = req.session.registerQQ;
  
  if (!qq_number) {
    return res.redirect('/register');
  }
  
  if (!password || password.length < 6) {
    return res.redirect('/register/password?error=密码长度至少6位');
  }
  
  if (password !== confirm_password) {
    return res.redirect('/register/password?error=两次输入的密码不一致');
  }
  
  try {
    // 创建用户
    const userData = {
      qq_openid: `MOCK_OPENID_${qq_number}`,
      qq_number: qq_number,
      nickname: `QQ用户${qq_number.slice(-4)}`,
      avatar: `https://q1.qlogo.cn/g?b=qq&nk=${qq_number}&s=100`
    };
    
    const user = User.create(userData);
    User.setPassword(user.id, password);
    
    // 清除session中的注册QQ号
    req.session.registerQQ = null;
    
    // 自动登录
    req.session.userId = user.id;
    req.session.justRegistered = true;
    
    res.redirect('/');
  } catch (error) {
    console.error('注册失败:', error.message);
    res.redirect(`/register/password?error=${encodeURIComponent(error.message)}`);
  }
});

// 模拟QQ登录页面（保留备用）
app.get('/auth/qq/mock', (req, res) => {
  if (config.useRealQQLogin) {
    return res.redirect('/login');
  }
  
  const state = req.query.state || '';
  
  res.render('mock-login', {
    title: '模拟QQ登录',
    state: state,
    mockUsers: config.mockUsers,
    adminQQ: config.adminQQ
  });
});

// 模拟登录提交（保留备用）
app.post('/auth/qq/mock', (req, res) => {
  if (config.useRealQQLogin) {
    return res.status(400).json({ error: '模拟登录已禁用' });
  }
  
  const { qq_number, state } = req.body;
  
  if (!qq_number) {
    return res.redirect('/login?error=请输入QQ号');
  }
  
  try {
    const user = qqAuth.mockLogin(qq_number);
    req.session.userId = user.id;
    req.session.oauthState = null;
    res.redirect('/');
  } catch (error) {
    console.error('模拟登录失败:', error);
    res.redirect('/login?error=登录失败，请重试');
  }
});

// QQ登录授权跳转
app.get('/auth/qq', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.oauthState = state;
  
  const authUrl = qqAuth.getQQAuthUrl(state);
  res.redirect(authUrl);
});

// QQ登录回调
app.get('/auth/qq/callback', async (req, res) => {
  const { code, state } = req.query;
  
  // 验证state
  if (!state || state !== req.session.oauthState) {
    return res.redirect('/login?error=状态验证失败，请重新登录');
  }
  
  if (!code) {
    return res.redirect('/login?error=授权失败，请重试');
  }
  
  try {
    const user = await qqAuth.handleQQLogin(code);
    req.session.userId = user.id;
    req.session.oauthState = null;
    res.redirect('/');
  } catch (error) {
    console.error('QQ登录失败:', error);
    res.redirect('/login?error=QQ登录失败，请重试');
  }
});

// 密码登录
app.post('/login/password', (req, res) => {
  const { qq_number, password } = req.body;
  
  if (!qq_number || !password) {
    return res.redirect('/login?error=请输入QQ号和密码');
  }
  
  const user = User.loginWithPassword(qq_number, password);
  if (user) {
    req.session.userId = user.id;
    res.redirect('/');
  } else {
    res.redirect('/login?error=QQ号或密码错误');
  }
});

// 退出登录
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// 设置密码页面
app.get('/settings/password', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  res.render('set-password', {
    title: '设置密码',
    success: req.query.success,
    error: req.query.error
  });
});

// 设置密码提交
app.post('/settings/password', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  const { old_password, new_password, confirm_password } = req.body;
  
  if (!new_password || new_password.length < 6) {
    return res.redirect('/settings/password?error=密码长度至少6位');
  }
  
  if (new_password !== confirm_password) {
    return res.redirect('/settings/password?error=两次输入的密码不一致');
  }
  
  const user = User.findById(req.session.userId);
  
  // 如果已有密码，需要验证旧密码
  if (user.password) {
    if (!old_password || !User.verifyPassword(req.session.userId, old_password)) {
      return res.redirect('/settings/password?error=旧密码错误');
    }
  }
  
  User.setPassword(req.session.userId, new_password);
  res.redirect('/settings/password?success=密码设置成功');
});

// 个人中心
app.get('/profile', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  const user = User.findById(req.session.userId);
  res.render('profile', {
    title: '个人中心',
    user: user
  });
});

// 绑定QQ号页面
app.post('/profile/bind-qq', (req, res) => {
  if (!req.session.userId) {
    return res.json({ success: false, error: '请先登录' });
  }
  
  const { qq_number } = req.body;
  
  if (!qq_number || !/^\d{5,12}$/.test(qq_number)) {
    return res.json({ success: false, error: '请输入有效的QQ号' });
  }
  
  // 检查QQ号是否已被绑定
  const existingUser = User.findByQQNumber(qq_number);
  if (existingUser && existingUser.id !== req.session.userId) {
    return res.json({ success: false, error: '该QQ号已被绑定' });
  }
  
  const user = User.update(req.session.userId, { qq_number: qq_number });
  
  // 更新session中的用户信息
  res.locals.currentUser = user;
  
  res.json({ success: true, user: { qq_number: user.qq_number, is_admin: user.is_admin } });
});

// ==================== 管理员功能 ====================

// 登录验证中间件
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    if (req.xhr || req.headers.accept?.includes('application/json') || req.path.startsWith('/api/')) {
      return res.status(401).json({ success: false, error: '请先登录' });
    }
    return res.redirect('/login');
  }
  next();
}

// 管理员中间件
function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  const user = User.findById(req.session.userId);
  if (!user || user.is_admin !== 1) {
    return res.status(403).render('error', {
      title: '权限不足',
      message: '您没有权限访问此页面'
    });
  }
  
  next();
}

// 网站编辑页面
app.get('/admin/edit', requireAdmin, (req, res) => {
  const pages = SiteContent.getAll();
  const currentPage = req.query.page || 'home';
  const content = SiteContent.getByPageName(currentPage);
  
  res.render('admin-edit', {
    title: '网站编辑',
    pages: pages,
    currentPage: currentPage,
    content: content,
    success: req.query.success
  });
});

// 保存网站内容
app.post('/admin/save', requireAdmin, (req, res) => {
  const { page_name, title, content } = req.body;
  
  if (!page_name || !title) {
    return res.redirect('/admin/edit?error=页面名称和标题不能为空');
  }
  
  SiteContent.update(page_name, title, content || '');
  res.redirect(`/admin/edit?page=${encodeURIComponent(page_name)}&success=保存成功`);
});

// 用户管理页面
app.get('/admin/users', requireAdmin, (req, res) => {
  const users = User.getAll();
  res.render('admin-users', {
    title: '用户管理',
    users: users,
    success: req.query.success,
    error: req.query.error
  });
});

// 封禁用户
app.post('/admin/users/ban', requireAdmin, (req, res) => {
  const { user_id, reason, ban_ip } = req.body;
  
  if (!user_id) {
    return res.json({ success: false, error: '用户ID不能为空' });
  }
  
  try {
    const user = User.banUser(parseInt(user_id), reason || '');
    
    // 如果选择同时封禁IP，且该用户有最后登录IP
    if (ban_ip && user.last_ip) {
      const adminName = req.session.userId ? (User.findById(req.session.userId)?.nickname || '管理员') : '管理员';
      BannedIP.add(user.last_ip, reason || '用户违规被封禁，关联IP封禁', adminName);
    }
    
    res.json({ success: true, user: user });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// 解封用户
app.post('/admin/users/unban', requireAdmin, (req, res) => {
  const { user_id, unban_ip } = req.body;
  
  if (!user_id) {
    return res.json({ success: false, error: '用户ID不能为空' });
  }
  
  try {
    const user = User.unbanUser(parseInt(user_id));
    
    // 如果选择同时解除IP封禁
    if (unban_ip && user.last_ip) {
      BannedIP.removeByIp(user.last_ip);
    }
    
    res.json({ success: true, user: user });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// IP封禁管理页面
app.get('/admin/banned-ips', requireAdmin, (req, res) => {
  const bannedIps = BannedIP.getAll();
  res.render('admin-banned-ips', {
    title: 'IP封禁管理',
    bannedIps: bannedIps,
    success: req.query.success,
    error: req.query.error
  });
});

// 添加IP封禁
app.post('/admin/banned-ips/add', requireAdmin, (req, res) => {
  const { ip, reason } = req.body;
  
  if (!ip) {
    return res.json({ success: false, error: 'IP地址不能为空' });
  }
  
  // 简单的IP格式验证
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipPattern.test(ip)) {
    return res.json({ success: false, error: 'IP地址格式不正确' });
  }
  
  try {
    const adminName = req.session.userId ? (User.findById(req.session.userId)?.nickname || '管理员') : '管理员';
    const bannedIp = BannedIP.add(ip, reason || '', adminName);
    res.json({ success: true, bannedIp: bannedIp });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// 解除IP封禁
app.post('/admin/banned-ips/remove', requireAdmin, (req, res) => {
  const { id } = req.body;
  
  if (!id) {
    return res.json({ success: false, error: 'ID不能为空' });
  }
  
  try {
    const result = BannedIP.remove(parseInt(id));
    if (result) {
      res.json({ success: true });
    } else {
      res.json({ success: false, error: '未找到该封禁记录' });
    }
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// ==================== 图片上传 ====================

// 确保上传目录存在
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// 配置multer存储
const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function(req, file, cb) {
    // 生成唯一文件名：时间戳 + 随机数 + 原扩展名
    const ext = path.extname(file.originalname).toLowerCase();
    const uniqueName = Date.now() + '_' + Math.random().toString(36).substring(2, 8) + ext;
    cb(null, uniqueName);
  }
});

// 文件过滤：只允许图片
const fileFilter = function(req, file, cb) {
  const allowedTypes = /jpeg|jpg|png|gif|webp|bmp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (extname && mimetype) {
    return cb(null, true);
  } else {
    cb(new Error('只允许上传图片文件（jpg, png, gif, webp）'));
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 限制5MB
  }
});

// 图片上传接口（管理员才能用）
app.post('/admin/upload-image', requireAdmin, (req, res) => {
  upload.single('image')(req, res, function(err) {
    if (err) {
      return res.json({ success: false, error: err.message });
    }
    
    if (!req.file) {
      return res.json({ success: false, error: '请选择要上传的图片' });
    }
    
    // 返回图片URL
    const imageUrl = '/uploads/' + req.file.filename;
    res.json({
      success: true,
      url: imageUrl,
      filename: req.file.filename
    });
  });
});

// 获取已上传的图片列表
app.get('/admin/images', requireAdmin, (req, res) => {
  try {
    const files = fs.readdirSync(uploadDir);
    const images = files
      .filter(file => /\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(file))
      .map(file => {
        const stat = fs.statSync(path.join(uploadDir, file));
        return {
          name: file,
          url: '/uploads/' + file,
          size: (stat.size / 1024).toFixed(1) + ' KB',
          created_at: stat.mtime.toISOString()
        };
      })
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    
    res.json({ success: true, images: images });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// 删除上传的图片
app.post('/admin/delete-image', requireAdmin, (req, res) => {
  const { filename } = req.body;
  
  if (!filename) {
    return res.json({ success: false, error: '文件名不能为空' });
  }
  
  // 安全检查：防止路径遍历
  if (filename.includes('/') || filename.includes('\\') || filename.includes('..')) {
    return res.json({ success: false, error: '无效的文件名' });
  }
  
  const filePath = path.join(uploadDir, filename);
  
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ success: true });
    } else {
      res.json({ success: false, error: '文件不存在' });
    }
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// 新增页面
app.post('/admin/new-page', requireAdmin, (req, res) => {
  const { page_name, title } = req.body;
  
  if (!page_name || !title) {
    return res.redirect('/admin/edit?error=页面名称和标题不能为空');
  }
  
  // 检查页面是否已存在
  const existing = SiteContent.getByPageName(page_name);
  if (existing) {
    return res.redirect('/admin/edit?error=该页面已存在');
  }
  
  SiteContent.update(page_name, title, '<p>新页面内容</p>');
  res.redirect(`/admin/edit?page=${encodeURIComponent(page_name)}&success=页面创建成功`);
});

// 自定义页面路由
app.get('/page/:pageName', (req, res) => {
  const pageName = req.params.pageName;
  const content = SiteContent.getByPageName(pageName);
  
  if (!content) {
    return res.status(404).render('error', {
      title: '页面不存在',
      message: '您访问的页面不存在'
    });
  }
  
  res.render('page', {
    title: content.title,
    content: content.content,
    pageName: pageName
  });
});

// ==================== 聊天室相关路由 ====================

// 获取当前登录用户信息
function getCurrentUser(req) {
  if (!req.session.userId) return null;
  const user = User.findById(req.session.userId);
  if (!user) return null;
  return {
    id: user.id,
    nickname: user.nickname || '用户',
    avatar: user.avatar || '',
    is_admin: user.is_admin
  };
}

// 聊天室页面（需要登录）
app.get('/chat', requireLogin, (req, res) => {
  const currentUser = getCurrentUser(req);
  res.render('chat', {
    title: '港州闲聊室',
    currentUser: currentUser
  });
});

// 获取最近聊天消息
app.get('/api/chat/messages', requireLogin, (req, res) => {
  const sinceId = parseInt(req.query.since_id) || 0;
  let messages;
  if (sinceId > 0) {
    messages = ChatMessage.getSince(sinceId);
  } else {
    messages = ChatMessage.getRecent(100);
  }
  res.json({ success: true, messages: messages });
});

// 发送文字消息
app.post('/api/chat/send', requireLogin, (req, res) => {
  const { content } = req.body;
  
  if (!content || !content.trim()) {
    return res.json({ success: false, error: '消息内容不能为空' });
  }
  
  if (content.length > 500) {
    return res.json({ success: false, error: '消息不能超过500字' });
  }
  
  const user = getCurrentUser(req);
  if (!user) {
    return res.json({ success: false, error: '用户信息无效' });
  }
  
  const message = ChatMessage.send(
    user.id,
    user.nickname,
    user.avatar || '',
    content.trim(),
    'text'
  );
  
  res.json({ success: true, message: message });
});

// 上传聊天图片（斗图）
app.post('/api/chat/upload-image', requireLogin, (req, res) => {
  upload.single('image')(req, res, function(err) {
    if (err) {
      return res.json({ success: false, error: err.message });
    }
    
    if (!req.file) {
      return res.json({ success: false, error: '请选择要上传的图片' });
    }
    
    const user = getCurrentUser(req);
    if (!user) {
      return res.json({ success: false, error: '用户信息无效' });
    }
    
    const imageUrl = '/uploads/' + req.file.filename;
    
    const message = ChatMessage.send(
      user.id,
      user.nickname,
      user.avatar || '',
      imageUrl,
      'image'
    );
    
    res.json({ success: true, message: message });
  });
});

// ==================== 反馈功能相关路由 ====================

// 反馈页面
app.get('/feedback', (req, res) => {
  const success = req.query.success || '';
  const error = req.query.error || '';
  res.render('feedback', {
    title: '意见反馈',
    success: success,
    error: error,
    currentUser: req.session.userId ? User.findById(req.session.userId) : null
  });
});

// 提交反馈
app.post('/feedback/submit', (req, res) => {
  const { name, email, type, content } = req.body;
  
  if (!content || !content.trim()) {
    return res.redirect('/feedback?error=反馈内容不能为空');
  }
  
  if (content.length > 1000) {
    return res.redirect('/feedback?error=反馈内容不能超过1000字');
  }
  
  const userId = req.session.userId || null;
  Feedback.submit(
    name?.trim(),
    email?.trim(),
    content.trim(),
    type || 'suggestion',
    userId
  );
  
  res.redirect('/feedback?success=反馈提交成功，感谢您的宝贵意见！');
});

// 管理员反馈管理页面
app.get('/admin/feedback', requireAdmin, (req, res) => {
  const feedbacks = Feedback.getAll();
  const stats = Feedback.getStats();
  res.render('admin-feedback', {
    title: '反馈管理',
    feedbacks: feedbacks,
    stats: stats,
    currentUser: User.findById(req.session.userId)
  });
});

// 更新反馈状态/回复
app.post('/admin/feedback/update', requireAdmin, (req, res) => {
  const { id, status, reply } = req.body;
  
  if (!id) {
    return res.json({ success: false, error: '参数错误' });
  }
  
  const result = Feedback.update(parseInt(id), status, reply);
  if (result) {
    res.json({ success: true });
  } else {
    res.json({ success: false, error: '反馈不存在' });
  }
});

// 删除反馈
app.post('/admin/feedback/delete', requireAdmin, (req, res) => {
  const { id } = req.body;
  
  if (!id) {
    return res.json({ success: false, error: '参数错误' });
  }
  
  const result = Feedback.delete(parseInt(id));
  if (result) {
    res.json({ success: true });
  } else {
    res.json({ success: false, error: '反馈不存在' });
  }
});

// ==================== 启动服务器 ====================

const os = require('os');
const PORT = config.server.port;
const HOST = config.server.host || '0.0.0.0';

// 获取本机局域网IP
function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

app.listen(PORT, HOST, () => {
  const localIP = getLocalIP();
  console.log(`
  ============================================
  🚀 网站已启动!
  📍 本地访问: http://localhost:${PORT}
  🌐 局域网访问: http://${localIP}:${PORT}
  🔑 管理员QQ号: ${config.adminQQ}
  📝 登录模式: ${config.useRealQQLogin ? '真实QQ登录' : '模拟登录模式'}
  ============================================
  
  快速登录测试:
  - 管理员账号 QQ: 18689326 (使用模拟登录)
  - 普通用户 QQ: 123456789 (使用模拟登录)
  
  💡 其他人可以通过局域网地址访问您的网站
  注意: 如需启用真实QQ登录，请修改 config.js 中的配置
  `);
});
