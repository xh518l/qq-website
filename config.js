// QQ登录配置
// 注意：真实QQ登录需要在 QQ互联(https://connect.qq.com/) 申请应用获取
// 默认使用模拟模式，方便本地测试
module.exports = {
  // 是否启用真实QQ登录（false为模拟模式）
  useRealQQLogin: false,  // 👈 改为 true 启用真实QQ登录
  
  // 真实QQ登录配置（需要在QQ互联申请）
  qq: {
    appId: 'YOUR_APP_ID',           // 👈 替换为你的APP ID
    appKey: 'YOUR_APP_KEY',         // 👈 替换为你的APP Key
    // 回调地址，需要在QQ互联中配置
    redirectUri: 'http://localhost:3000/auth/qq/callback'
  },
  
  // 模拟QQ登录的测试账号
  mockUsers: [
    {
      qq_openid: 'MOCK_OPENID_18689326',
      qq_number: '18689326',
      nickname: '管理员',
      avatar: 'https://q1.qlogo.cn/g?b=qq&nk=18689326&s=100'
    },
    {
      qq_openid: 'MOCK_OPENID_123456789',
      qq_number: '123456789',
      nickname: '测试用户',
      avatar: 'https://q1.qlogo.cn/g?b=qq&nk=123456789&s=100'
    }
  ],
  
  // 服务器配置
  server: {
    port: 3000,
    host: '0.0.0.0', // 监听所有网卡，支持外部访问
    sessionSecret: 'qq-website-secret-key-change-in-production'
  },
  
  // 管理员QQ号
  adminQQ: '18689326'
};
