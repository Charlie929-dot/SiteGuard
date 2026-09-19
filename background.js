// ============================================================
// SiteGuard - 后台 Background Page（MV2）
// 负责：监听标签页切换，触发域名分析，更新地址栏图标
// 依赖脚本由 manifest.json 的 background.scripts 按顺序加载
// ============================================================

// 域名分析结果缓存（内存缓存 + chrome.storage.local 持久化）
const analysisCache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 小时
const CACHE_STORAGE_KEY = 'analysisCache';

/**
 * 读取 chrome.storage.local（回调风格，兼容 Chrome / Firefox MV2）
 */
function storageGet(key) {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.get(key, (result) => {
        if (chrome.runtime.lastError) { resolve(null); return; }
        resolve(result);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

/**
 * 写入 chrome.storage.local（回调风格）
 */
function storageSet(obj) {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.set(obj, () => resolve(true));
    } catch (e) {
      resolve(false);
    }
  });
}

/**
 * 从 storage 加载缓存到内存（后台页启动时调用）
 */
async function loadCacheFromStorage() {
  const result = await storageGet(CACHE_STORAGE_KEY);
  const cache = result && result[CACHE_STORAGE_KEY];
  if (cache && typeof cache === 'object') {
    for (const domain of Object.keys(cache)) {
      analysisCache.set(domain, cache[domain]);
    }
  }
}

/**
 * 将内存缓存持久化到 storage
 */
async function persistCache() {
  const obj = {};
  for (const [domain, entry] of analysisCache.entries()) {
    obj[domain] = entry;
  }
  await storageSet({ [CACHE_STORAGE_KEY]: obj });
}

/**
 * 清空所有缓存（内存 + storage）
 */
async function clearCache() {
  analysisCache.clear();
  await storageSet({ [CACHE_STORAGE_KEY]: {} });
}

// 跟踪当前活动标签页（供 popup 在直接 query 失败时兜底获取 URL）
let activeTabId = null;
let activeTabUrl = null;

// 图标路径映射
const ICON_PATHS = {
  gray: {
    16: 'icons/gray-16.png', 32: 'icons/gray-32.png',
    48: 'icons/gray-48.png', 128: 'icons/gray-128.png'
  },
  green: {
    16: 'icons/green-16.png', 32: 'icons/green-32.png',
    48: 'icons/green-48.png', 128: 'icons/green-128.png'
  },
  yellow: {
    16: 'icons/yellow-16.png', 32: 'icons/yellow-32.png',
    48: 'icons/yellow-48.png', 128: 'icons/yellow-128.png'
  },
  red: {
    16: 'icons/red-16.png', 32: 'icons/red-32.png',
    48: 'icons/red-48.png', 128: 'icons/red-128.png'
  }
};

/**
 * 根据安全评分确定图标状态
 */
function getIconState(analysis) {
  if (!analysis || !analysis.score) return 'gray';
  if (analysis.score.total === null) return 'gray'; // 数据不足，未知
  if (analysis.score.total >= 80) return 'green';
  if (analysis.score.total >= 60) return 'yellow';
  return 'red';
}

/**
 * 更新指定标签页的地址栏图标
 */
async function updateTabIcon(tabId, iconState) {
  const iconPaths = ICON_PATHS[iconState] || ICON_PATHS.gray;
  try {
    await chrome.browserAction.setIcon({
      tabId,
      path: iconPaths
    });
  } catch (e) {
    // 标签页可能已关闭
    console.warn('[SiteGuard] 设置图标失败', e.message);
  }
}

/**
 * 分析某个 URL 对应的域名
 * @param {string} url 完整 URL
 * @returns {Promise<Object|null>} 分析结果
 */
async function analyzeUrl(url) {
  if (!url || !/^https?:\/\//i.test(url)) return null;

  const hostname = extractHostname(url);
  const mainDomain = getMainDomain(url);
  if (!mainDomain || isIPAddress(hostname)) {
    return { domain: null, reason: 'invalid', isIp: true };
  }

  // 检查缓存
  const cached = analysisCache.get(mainDomain);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
    return cached.data;
  }

  // 并行查询各维度数据
  const [whois, icp] = await Promise.all([
    queryWhois(mainDomain),
    queryIcp(mainDomain)
  ]);

  // 官方域名池比对（本地，无需网络；传完整主机名以支持子域名条目命中）
  const official = analyzeOfficialDomain(hostname);

  // 计算综合评分
  const score = computeSecurityScore({ domain: mainDomain, whois, icp, official });

  const result = {
    domain: mainDomain,
    whois,
    icp,
    official,
    score,
    timestamp: Date.now()
  };

  // 写入缓存（内存 + 持久化到 storage）
  analysisCache.set(mainDomain, { data: result, timestamp: Date.now() });
  persistCache();

  return result;
}

/**
 * 处理标签页激活/更新事件
 */
async function handleTab(tabId, url) {
  const analysis = await analyzeUrl(url);
  const iconState = getIconState(analysis);
  await updateTabIcon(tabId, iconState);
}

// 监听标签页激活
chrome.tabs.onActivated.addListener(({ tabId }) => {
  activeTabId = tabId;
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError) {
      console.warn('[SiteGuard] 获取标签页失败', chrome.runtime.lastError.message);
      return;
    }
    if (tab && tab.url) {
      activeTabUrl = tab.url;
      handleTab(tabId, tab.url);
    }
  });
});

// 监听标签页更新（导航）
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    if (tabId === activeTabId) {
      activeTabUrl = tab.url;
    }
    await handleTab(tabId, tab.url);
  }
});

// 监听来自 popup 的消息
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_URL') {
    analyzeUrl(message.url).then(analysis => {
      sendResponse({ success: true, analysis });
    }).catch(err => {
      sendResponse({ success: false, error: err.message });
    });
    return true; // 异步响应
  }

  if (message.type === 'GET_OFFICIAL_COUNT') {
    sendResponse({ count: getOfficialDomainCount() });
    return false;
  }

  if (message.type === 'GET_ACTIVE_TAB') {
    sendResponse({ url: activeTabUrl || null });
    return false;
  }

  if (message.type === 'CLEAR_CACHE') {
    clearCache().then(() => {
      sendResponse({ success: true });
    }).catch((err) => {
      console.warn('[SiteGuard] 清除缓存失败', err && err.message);
      sendResponse({ success: false });
    });
    return true; // 异步响应
  }
});

loadCacheFromStorage().then(() => {
  console.log('[SiteGuard] 后台服务已启动，缓存已加载');
});
