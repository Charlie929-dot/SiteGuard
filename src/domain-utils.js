// ============================================================
// SiteGuard - 域名工具函数
// 负责：提取主域名、注册域、域名规范化
// ============================================================

// 常见公共后缀（eTLD+1 判断用），MVP 阶段用简化版列表
const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
  'cn', 'com.cn', 'net.cn', 'org.cn', 'edu.cn', 'gov.cn', 'ac.cn', 'mil.cn',
  'co', 'io', 'ai', 'app', 'dev', 'me', 'tv', 'cc', 'top', 'xyz', 'info', 'biz',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'com.hk', 'org.hk', 'edu.hk', 'gov.hk',
  'com.tw', 'org.tw', 'edu.tw', 'gov.tw',
  'com.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'de', 'fr', 'nl', 'eu', 'ru', 'com.ru', 'jp', 'kr', 'co.kr', 'go.kr',
  'com.mx', 'com.br', 'in', 'co.in', 'us', 'ca', 'com.my', 'com.sg'
]);

/**
 * 从完整 URL 提取主机名（去掉协议、路径、端口、query）
 */
function extractHostname(url) {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

/**
 * 计算可注册域（registrable domain，即 eTLD+1）
 * 例如：login.people.com.cn -> people.com.cn
 */
function getRegistrableDomain(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');

  // 尝试匹配公共后缀
  for (let i = 0; i < parts.length - 1; i++) {
    const suffix = parts.slice(i + 1).join('.');
    if (PUBLIC_SUFFIXES.has(suffix)) {
      return parts.slice(i).join('.');
    }
  }
  // 兜底：取最后两段
  return parts.slice(-2).join('.');
}

/**
 * 去除子域名，得到主域名（注册域）
 */
function getMainDomain(url) {
  const hostname = extractHostname(url);
  if (!hostname) return null;
  return getRegistrableDomain(hostname);
}

/**
 * 判断是否为 IP 地址
 */
function isIPAddress(hostname) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  if (hostname.includes(':')) return true; // IPv6
  return false;
}

/**
 * 域名规范化（用于比对，去掉 www. 前缀等）
 */
function normalizeDomain(domain) {
  return domain.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
}
