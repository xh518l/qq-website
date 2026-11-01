const axios = require('axios');
const config = require('./config');
const { User } = require('./database');

/**
 * QQ登录认证模块
 * 支持真实OAuth2.0登录和模拟登录两种模式
 */

// 获取QQ登录授权URL
function getQQAuthUrl(state) {
  if (!config.useRealQQLogin) {
    // 模拟模式：返回模拟登录页面路径
    return `/auth/qq/mock?state=${encodeURIComponent(state)}`;
  }
  
  // 真实QQ登录授权URL
  const authUrl = 'https://graph.qq.com/oauth2.0/authorize';
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.qq.appId,
    redirect_uri: config.qq.redirectUri,
    state: state,
    scope: 'get_user_info'
  });
  
  return `${authUrl}?${params.toString()}`;
}

// 通过授权码获取access_token
async function getAccessToken(code) {
  if (!config.useRealQQLogin) {
    // 模拟模式
    return { access_token: 'MOCK_ACCESS_TOKEN' };
  }
  
  try {
    const tokenUrl = 'https://graph.qq.com/oauth2.0/token';
    const response = await axios.get(tokenUrl, {
      params: {
        grant_type: 'authorization_code',
        client_id: config.qq.appId,
        client_secret: config.qq.appKey,
        code: code,
        redirect_uri: config.qq.redirectUri
      }
    });
    
    // QQ返回的是 query string 格式
    const params = new URLSearchParams(response.data);
    return {
      access_token: params.get('access_token'),
      expires_in: params.get('expires_in'),
      refresh_token: params.get('refresh_token')
    };
  } catch (error) {
    console.error('获取access_token失败:', error.message);
    throw new Error('获取QQ访问令牌失败');
  }
}

// 通过access_token获取用户openid
async function getOpenId(accessToken) {
  if (!config.useRealQQLogin) {
    // 模拟模式：返回第一个测试用户的openid
    return {
      openid: config.mockUsers[0].qq_openid,
      client_id: config.qq.appId
    };
  }
  
  try {
    const meUrl = 'https://graph.qq.com/oauth2.0/me';
    const response = await axios.get(meUrl, {
      params: { access_token: accessToken }
    });
    
    // QQ返回的是 callback(...) 格式的JSONP
    const jsonStr = response.data.replace(/callback\((.*)\);/, '$1');
    const data = JSON.parse(jsonStr);
    
    if (data.error) {
      throw new Error(data.error_description || '获取openid失败');
    }
    
    return data;
  } catch (error) {
    console.error('获取openid失败:', error.message);
    throw new Error('获取QQ用户ID失败');
  }
}

// 获取用户信息
async function getUserInfo(accessToken, openid) {
  if (!config.useRealQQLogin) {
    // 模拟模式：返回模拟用户信息
    const mockUser = config.mockUsers.find(u => u.qq_openid === openid);
    if (mockUser) {
      return {
        nickname: mockUser.nickname,
        figureurl_qq_2: mockUser.avatar,
        openid: openid
      };
    }
    return {
      nickname: 'QQ用户',
      figureurl_qq_2: '',
      openid: openid
    };
  }
  
  try {
    const userInfoUrl = 'https://graph.qq.com/user/get_user_info';
    const response = await axios.get(userInfoUrl, {
      params: {
        access_token: accessToken,
        oauth_consumer_key: config.qq.appId,
        openid: openid
      }
    });
    
    const data = response.data;
    if (data.ret !== 0) {
      throw new Error(data.msg || '获取用户信息失败');
    }
    
    return data;
  } catch (error) {
    console.error('获取用户信息失败:', error.message);
    throw new Error('获取QQ用户信息失败');
  }
}

// 处理QQ登录回调，返回或创建用户
async function handleQQLogin(code) {
  // 1. 获取access_token
  const tokenData = await getAccessToken(code);
  
  // 2. 获取openid
  const openIdData = await getOpenId(tokenData.access_token);
  const openid = openIdData.openid;
  
  // 3. 查找用户是否已存在
  let user = User.findByOpenId(openid);
  
  if (user) {
    // 用户已存在，更新信息
    const userInfo = await getUserInfo(tokenData.access_token, openid);
    user = User.update(user.id, {
      nickname: userInfo.nickname,
      avatar: userInfo.figureurl_qq_2 || userInfo.figureurl_qq_1 || ''
    });
  } else {
    // 新用户，创建账户
    const userInfo = await getUserInfo(tokenData.access_token, openid);
    user = User.create({
      qq_openid: openid,
      nickname: userInfo.nickname,
      avatar: userInfo.figureurl_qq_2 || userInfo.figureurl_qq_1 || ''
    });
  }
  
  return user;
}

// 模拟登录 - 根据QQ号模拟登录
function mockLogin(qqNumber) {
  const mockUser = config.mockUsers.find(u => u.qq_number === qqNumber);
  if (!mockUser) {
    // 如果不是预设的模拟用户，创建一个模拟用户
    const mockData = {
      qq_openid: `MOCK_OPENID_${qqNumber}`,
      qq_number: qqNumber,
      nickname: `QQ用户${qqNumber.slice(-4)}`,
      avatar: `https://q1.qlogo.cn/g?b=qq&nk=${qqNumber}&s=100`
    };
    
    let user = User.findByOpenId(mockData.qq_openid);
    if (!user) {
      user = User.create(mockData);
    }
    return user;
  }
  
  let user = User.findByOpenId(mockUser.qq_openid);
  if (!user) {
    user = User.create(mockUser);
  }
  return user;
}

module.exports = {
  getQQAuthUrl,
  handleQQLogin,
  mockLogin,
  getUserInfo
};
