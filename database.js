const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const dataDir = path.join(__dirname, 'data');
const usersFile = path.join(dataDir, 'users.json');
const contentFile = path.join(dataDir, 'content.json');
const bannedIpsFile = path.join(dataDir, 'banned_ips.json');
const chatMessagesFile = path.join(dataDir, 'chat_messages.json');
const feedbackFile = path.join(dataDir, 'feedback.json');

// 确保数据目录存在
function ensureDataDir() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
}

// 读取用户数据
function readUsers() {
  ensureDataDir();
  if (!fs.existsSync(usersFile)) {
    return [];
  }
  try {
    const data = fs.readFileSync(usersFile, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

// 写入用户数据
function writeUsers(users) {
  ensureDataDir();
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2), 'utf8');
}

// 读取网站内容数据
function readContent() {
  ensureDataDir();
  if (!fs.existsSync(contentFile)) {
    return [];
  }
  try {
    const data = fs.readFileSync(contentFile, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

// 写入网站内容数据
function writeContent(content) {
  ensureDataDir();
  fs.writeFileSync(contentFile, JSON.stringify(content, null, 2), 'utf8');
}

// 生成自增ID
function getNextId(array) {
  if (array.length === 0) return 1;
  return Math.max(...array.map(item => item.id)) + 1;
}

// 初始化数据库
function initDB() {
  ensureDataDir();
  
  // 初始化默认首页内容
  const content = readContent();
  const homePage = content.find(p => p.page_name === 'home');
  if (!homePage) {
    content.push({
      id: 1,
      page_name: 'home',
      title: '欢迎来到QQ登录网站',
      content: '<h2>欢迎访问我们的网站！</h2><p>这是一个支持QQ登录的网站，您可以使用QQ账号快速登录。</p><p>登录后可以设置密码，管理员还可以编辑网站内容。</p>',
      updated_at: new Date().toISOString()
    });
    writeContent(content);
  }
  
  // 确保管理员账号存在并有默认密码
  const adminQQ = '18689326';
  const defaultAdminPassword = 'admin123';
  let adminUser = null;
  
  const users = readUsers();
  const existingAdmin = users.find(u => u.qq_number === adminQQ);
  
  if (existingAdmin) {
    adminUser = existingAdmin;
    // 如果管理员没有密码，设置默认密码
    if (!existingAdmin.password) {
      const hashedPassword = bcrypt.hashSync(defaultAdminPassword, 10);
      existingAdmin.password = hashedPassword;
      existingAdmin.is_admin = 1;
      writeUsers(users);
      console.log(`管理员默认密码已设置: ${defaultAdminPassword}`);
    }
  }
  
  console.log('数据存储初始化完成');
}

// 用户相关操作
const User = {
  // 根据QQ openid查找用户
  findByOpenId: function(openid) {
    const users = readUsers();
    return users.find(u => u.qq_openid === openid) || null;
  },

  // 根据QQ号查找用户
  findByQQNumber: function(qqNumber) {
    const users = readUsers();
    return users.find(u => u.qq_number === qqNumber) || null;
  },

  // 根据ID查找用户
  findById: function(id) {
    const users = readUsers();
    return users.find(u => u.id === id) || null;
  },

  // 创建新用户
  create: function(userData) {
    const users = readUsers();
    
    // 检查QQ号是否已被注册（如果有QQ号的话）
    if (userData.qq_number) {
      const existingUser = users.find(u => u.qq_number === userData.qq_number);
      if (existingUser) {
        throw new Error('该QQ号已注册账号，请直接登录');
      }
    }
    
    // 检查openid是否已存在
    if (userData.qq_openid) {
      const existingUser = users.find(u => u.qq_openid === userData.qq_openid);
      if (existingUser) {
        throw new Error('该QQ账号已注册，请直接登录');
      }
    }
    
    const isAdmin = userData.qq_number === '18689326' ? 1 : 0;
    const newUser = {
      id: getNextId(users),
      qq_openid: userData.qq_openid || null,
      qq_number: userData.qq_number || '',
      nickname: userData.nickname || '',
      avatar: userData.avatar || '',
      password: null,
      is_admin: isAdmin,
      is_banned: 0,
      ban_reason: '',
      banned_at: null,
      last_ip: '',
      last_login_at: null,
      created_at: new Date().toISOString()
    };
    users.push(newUser);
    writeUsers(users);
    return newUser;
  },

  // 更新用户信息
  update: function(id, userData) {
    const users = readUsers();
    const index = users.findIndex(u => u.id === id);
    if (index === -1) return null;
    
    if (userData.nickname !== undefined) {
      users[index].nickname = userData.nickname;
    }
    if (userData.avatar !== undefined) {
      users[index].avatar = userData.avatar;
    }
    if (userData.qq_number !== undefined) {
      users[index].qq_number = userData.qq_number;
      // 如果QQ号是管理员QQ号，设置为管理员
      if (userData.qq_number === '18689326') {
        users[index].is_admin = 1;
      }
    }
    
    writeUsers(users);
    return users[index];
  },

  // 设置密码
  setPassword: function(id, password) {
    const users = readUsers();
    const index = users.findIndex(u => u.id === id);
    if (index === -1) return false;
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    users[index].password = hashedPassword;
    writeUsers(users);
    return true;
  },

  // 验证密码
  verifyPassword: function(id, password) {
    const user = this.findById(id);
    if (!user || !user.password) return false;
    return bcrypt.compareSync(password, user.password);
  },

  // 使用密码登录（通过QQ号）
  loginWithPassword: function(qqNumber, password) {
    const user = this.findByQQNumber(qqNumber);
    if (!user || !user.password) return null;
    if (bcrypt.compareSync(password, user.password)) {
      return user;
    }
    return null;
  },

  // 记录用户登录信息（IP和时间）
  updateLoginInfo: function(userId, ip) {
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return null;
    
    users[index].last_ip = ip || '';
    users[index].last_login_at = new Date().toISOString();
    writeUsers(users);
    return users[index];
  },

  // 获取所有用户
  getAll: function() {
    const users = readUsers();
    return users.map(u => ({
      id: u.id,
      qq_number: u.qq_number,
      nickname: u.nickname,
      is_admin: u.is_admin,
      is_banned: u.is_banned || 0,
      ban_reason: u.ban_reason || '',
      banned_at: u.banned_at || null,
      last_ip: u.last_ip || '',
      last_login_at: u.last_login_at || null,
      created_at: u.created_at
    })).sort((a, b) => b.id - a.id);
  },

  // 封禁用户
  banUser: function(userId, reason) {
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return null;
    
    // 不能封禁管理员
    if (users[index].is_admin === 1) {
      throw new Error('不能封禁管理员账号');
    }
    
    users[index].is_banned = 1;
    users[index].ban_reason = reason || '';
    users[index].banned_at = new Date().toISOString();
    writeUsers(users);
    return users[index];
  },

  // 解封用户
  unbanUser: function(userId) {
    const users = readUsers();
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return null;
    
    users[index].is_banned = 0;
    users[index].ban_reason = '';
    users[index].banned_at = null;
    writeUsers(users);
    return users[index];
  }
};

// 网站内容相关操作
const SiteContent = {
  // 获取页面内容
  getByPageName: function(pageName) {
    const content = readContent();
    return content.find(p => p.page_name === pageName) || null;
  },

  // 更新页面内容
  update: function(pageName, title, content) {
    const pages = readContent();
    const index = pages.findIndex(p => p.page_name === pageName);
    
    if (index !== -1) {
      pages[index].title = title;
      pages[index].content = content;
      pages[index].updated_at = new Date().toISOString();
    } else {
      pages.push({
        id: getNextId(pages),
        page_name: pageName,
        title: title,
        content: content,
        updated_at: new Date().toISOString()
      });
    }
    
    writeContent(pages);
    return this.getByPageName(pageName);
  },

  // 获取所有页面
  getAll: function() {
    const content = readContent();
    return content.map(p => ({
      id: p.id,
      page_name: p.page_name,
      title: p.title,
      updated_at: p.updated_at
    })).sort((a, b) => a.id - b.id);
  }
};

// 读取封禁IP数据
function readBannedIps() {
  ensureDataDir();
  if (!fs.existsSync(bannedIpsFile)) {
    return [];
  }
  try {
    const data = fs.readFileSync(bannedIpsFile, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

// 写入封禁IP数据
function writeBannedIps(ips) {
  fs.writeFileSync(bannedIpsFile, JSON.stringify(ips, null, 2));
}

// IP封禁相关操作
const BannedIP = {
  // 检查IP是否被封禁
  isBanned: function(ip) {
    const bannedIps = readBannedIps();
    return bannedIps.find(b => b.ip === ip && b.is_active === 1) || null;
  },

  // 获取所有封禁IP
  getAll: function() {
    const bannedIps = readBannedIps();
    return bannedIps.sort((a, b) => b.id - a.id);
  },

  // 添加封禁IP
  add: function(ip, reason, bannedBy) {
    const bannedIps = readBannedIps();
    
    // 检查是否已存在该IP的封禁记录
    const existing = bannedIps.find(b => b.ip === ip && b.is_active === 1);
    if (existing) {
      return existing; // 已封禁，直接返回
    }
    
    const newBan = {
      id: bannedIps.length > 0 ? Math.max(...bannedIps.map(b => b.id)) + 1 : 1,
      ip: ip,
      reason: reason || '',
      banned_by: bannedBy || '',
      is_active: 1,
      banned_at: new Date().toISOString(),
      unbanned_at: null
    };
    bannedIps.push(newBan);
    writeBannedIps(bannedIps);
    return newBan;
  },

  // 解除IP封禁
  remove: function(id) {
    const bannedIps = readBannedIps();
    const index = bannedIps.findIndex(b => b.id === id);
    if (index === -1) return null;
    
    bannedIps[index].is_active = 0;
    bannedIps[index].unbanned_at = new Date().toISOString();
    writeBannedIps(bannedIps);
    return bannedIps[index];
  },

  // 通过IP地址解除封禁
  removeByIp: function(ip) {
    const bannedIps = readBannedIps();
    let updated = null;
    bannedIps.forEach(b => {
      if (b.ip === ip && b.is_active === 1) {
        b.is_active = 0;
        b.unbanned_at = new Date().toISOString();
        updated = b;
      }
    });
    if (updated) {
      writeBannedIps(bannedIps);
    }
    return updated;
  }
};

// 读取聊天消息数据
function readChatMessages() {
  ensureDataDir();
  if (!fs.existsSync(chatMessagesFile)) {
    return [];
  }
  try {
    const data = fs.readFileSync(chatMessagesFile, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

// 写入聊天消息数据
function writeChatMessages(messages) {
  fs.writeFileSync(chatMessagesFile, JSON.stringify(messages, null, 2));
}

// 聊天消息相关操作
const ChatMessage = {
  // 获取最近的消息（默认最近100条）
  getRecent: function(limit = 100) {
    const messages = readChatMessages();
    const recent = messages.slice(-limit);
    return recent.map(m => ({
      id: m.id,
      user_id: m.user_id,
      nickname: m.nickname,
      avatar: m.avatar,
      content: m.content,
      type: m.type || 'text', // text, image
      created_at: m.created_at
    }));
  },

  // 发送消息
  send: function(userId, nickname, avatar, content, type = 'text') {
    const messages = readChatMessages();
    
    const newMessage = {
      id: messages.length > 0 ? Math.max(...messages.map(m => m.id)) + 1 : 1,
      user_id: userId,
      nickname: nickname,
      avatar: avatar || '',
      content: content,
      type: type,
      created_at: new Date().toISOString()
    };
    
    messages.push(newMessage);
    
    // 只保留最近500条消息
    if (messages.length > 500) {
      messages.splice(0, messages.length - 500);
    }
    
    writeChatMessages(messages);
    return newMessage;
  },

  // 获取最新消息ID之后的消息
  getSince: function(sinceId) {
    const messages = readChatMessages();
    const newMessages = messages.filter(m => m.id > sinceId);
    return newMessages.map(m => ({
      id: m.id,
      user_id: m.user_id,
      nickname: m.nickname,
      avatar: m.avatar,
      content: m.content,
      type: m.type || 'text',
      created_at: m.created_at
    }));
  }
};

// 读取反馈数据
function readFeedback() {
  ensureDataDir();
  if (!fs.existsSync(feedbackFile)) {
    return [];
  }
  try {
    const data = fs.readFileSync(feedbackFile, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    return [];
  }
}

// 写入反馈数据
function writeFeedback(feedbacks) {
  fs.writeFileSync(feedbackFile, JSON.stringify(feedbacks, null, 2));
}

// 反馈相关操作
const Feedback = {
  // 获取所有反馈
  getAll: function() {
    const feedbacks = readFeedback();
    return feedbacks.sort((a, b) => b.id - a.id);
  },

  // 提交反馈
  submit: function(name, email, content, type, userId = null) {
    const feedbacks = readFeedback();
    
    const newFeedback = {
      id: feedbacks.length > 0 ? Math.max(...feedbacks.map(f => f.id)) + 1 : 1,
      user_id: userId,
      name: name || '匿名用户',
      email: email || '',
      type: type || 'suggestion', // suggestion, bug, question, other
      content: content,
      status: 'pending', // pending, processing, resolved
      reply: '',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    
    feedbacks.push(newFeedback);
    writeFeedback(feedbacks);
    return newFeedback;
  },

  // 获取单个反馈
  getById: function(id) {
    const feedbacks = readFeedback();
    return feedbacks.find(f => f.id === id) || null;
  },

  // 回复/更新反馈状态
  update: function(id, status, reply) {
    const feedbacks = readFeedback();
    const index = feedbacks.findIndex(f => f.id === id);
    if (index === -1) return null;
    
    if (status) feedbacks[index].status = status;
    if (reply !== undefined) feedbacks[index].reply = reply;
    feedbacks[index].updated_at = new Date().toISOString();
    
    writeFeedback(feedbacks);
    return feedbacks[index];
  },

  // 删除反馈
  delete: function(id) {
    const feedbacks = readFeedback();
    const index = feedbacks.findIndex(f => f.id === id);
    if (index === -1) return false;
    
    feedbacks.splice(index, 1);
    writeFeedback(feedbacks);
    return true;
  },

  // 获取统计
  getStats: function() {
    const feedbacks = readFeedback();
    return {
      total: feedbacks.length,
      pending: feedbacks.filter(f => f.status === 'pending').length,
      processing: feedbacks.filter(f => f.status === 'processing').length,
      resolved: feedbacks.filter(f => f.status === 'resolved').length
    };
  }
};

module.exports = {
  initDB,
  User,
  SiteContent,
  BannedIP,
  ChatMessage,
  Feedback
};
