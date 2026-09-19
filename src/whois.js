// ============================================================
// SiteGuard - WHOIS 查询模块
// 主数据源：天行数据 TianAPI（https://apis.tianapi.com/whois/index）
// 兜底：RDAP 协议（官方标准，免费）
// ============================================================

// 天行数据 WHOIS 接口配置
const TIANAPI_KEY = 'cb3e5ac6c0c94733bb638aeb09bae351';
const TIANAPI_URL = 'https://apis.tianapi.com/whois/index';

// RDAP 兜底端点（rdap.org 会按 IANA bootstrap 自动重定向到对应注册局）
const RDAP_BOOTSTRAP = {
  'default': 'https://rdap.org/domain/',
  'com': 'https://rdap.verisign.com/com/v1/domain/',
  'net': 'https://rdap.verisign.com/net/v1/domain/',
};

function getRdapEndpoint(tld) {
  return RDAP_BOOTSTRAP[tld] || RDAP_BOOTSTRAP['default'];
}

/**
 * 归一化日期字符串为 ISO 8601（UTC 零点）
 * 天行实际返回形如 "2000-09-28 00:00:00"（空格分隔、无时区，北京时间），
 * 文档示例又可能是 "2016-06-28 T08:48:10Z"。
 * 对域名年龄/到期判断而言只需日期精度，故统一提取日期部分、按 UTC 零点处理，
 * 避免本地时区偏移造成 ±8 小时误差
 */
function normalizeDate(str) {
  if (!str) return null;
  const s = String(str).trim();
  if (!s) return null;

  const m = s.match(/(\d{4})-(\d{1,2})-(\d{1,2})/);
  if (!m) return null;

  const y = m[1];
  const mo = m[2].padStart(2, '0');
  const d = m[3].padStart(2, '0');
  return `${y}-${mo}-${d}T00:00:00.000Z`;
}

/**
 * 判断是否启用隐私保护（基于注册人/邮箱字段）
 */
function detectPrivacy(registrant, email) {
  const s = `${registrant || ''} ${email || ''}`.toUpperCase();
  const keywords = ['REDACTED', 'PRIVACY', 'WHOISGUARD', 'PROXY', '保护', '隐私'];
  return keywords.some(k => s.includes(k));
}

/**
 * 天行数据 WHOIS 查询（主数据源）
 * @returns {Promise<Object|null>}
 */
async function queryWhoisTianApi(domain) {
  const url = `${TIANAPI_URL}?key=${encodeURIComponent(TIANAPI_KEY)}&domain=${encodeURIComponent(domain)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const resp = await fetch(url, { signal: controller.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data = await resp.json();
    if (data.code !== 200 || !data.result) {
      console.warn(`[SiteGuard] 天行 WHOIS 异常: ${domain} code=${data.code} msg=${data.msg}`);
      return null;
    }

    const r = data.result;
    return {
      domain: domain,
      registrationDate: normalizeDate(r.creation_date),
      expirationDate: normalizeDate(r.expiration_date),
      lastChangedDate: null,
      registrar: r.registrar || '未知',
      registrant: r.registrant || null,
      email: r.email || null,
      phone: r.phone || null,
      status: r.status || null,
      privacyProtection: detectPrivacy(r.registrant, r.email),
      raw: r
    };
  } catch (err) {
    console.warn(`[SiteGuard] 天行 WHOIS 查询失败: ${domain}`, err.message);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * 发起 RDAP 请求并解析 JSON（失败返回 null）
 */
async function fetchRdapJson(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { 'Accept': 'application/rdap+json, application/json' }
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch (e) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function rdapHasEvents(data) {
  return !!(data && Array.isArray(data.events) && data.events.length > 0);
}

/**
 * 从 RDAP 响应中找注册商 RDAP 的 related 链接（瘦数据时用）
 * 例如 verisign 的 .com 瘦响应会带 rel=related -> rdap.dnspod.cn/domain/xxx
 */
function findRelatedUrl(data) {
  if (!data || !Array.isArray(data.links)) return null;
  for (const link of data.links) {
    if (link.rel === 'related' && typeof link.href === 'string' && /^https?:\/\//i.test(link.href)) {
      return link.href;
    }
  }
  return null;
}

/**
 * 从 RDAP 数据中解析注册/到期时间
 */
function parseRdapDates(data) {
  let registrationDate = null, expirationDate = null;
  if (Array.isArray(data.events)) {
    for (const ev of data.events) {
      if (ev.eventAction === 'registration') registrationDate = ev.eventDate;
      else if (ev.eventAction === 'expiration') expirationDate = ev.eventDate;
    }
  }
  return { registrationDate, expirationDate };
}

/**
 * 从 RDAP entities 中解析注册商名称
 */
function parseRdapRegistrar(data) {
  if (!data || !Array.isArray(data.entities)) return '未知';
  for (const ent of data.entities) {
    if ((ent.roles || []).includes('registrar')) {
      const vcard = ent.vcardArray;
      if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
        for (const prop of vcard[1]) {
          if (Array.isArray(prop) && prop[0] === 'fn' && prop.length >= 4) {
            return prop[3];
          }
        }
      }
      if (ent.handle) return ent.handle;
    }
  }
  return '未知';
}

/**
 * RDAP 查询（兜底）
 * @returns {Promise<Object|null>}
 */
async function queryWhoisRdap(domain) {
  const parts = domain.split('.');
  const tld = parts.slice(1).join('.').toLowerCase();
  let data = await fetchRdapJson(getRdapEndpoint(tld) + domain);
  if (!data) return null;

  // 瘦数据（如 verisign .com 只返回注册商 handle，无 events）→ 跟随 related 链接到注册商 RDAP
  if (!rdapHasEvents(data)) {
    const relatedUrl = findRelatedUrl(data);
    if (relatedUrl) {
      const related = await fetchRdapJson(relatedUrl);
      if (related) data = related;
    }
  }

  const { registrationDate, expirationDate } = parseRdapDates(data);
  const registrar = parseRdapRegistrar(data);

  const json = JSON.stringify(data).toUpperCase();
  const privacyProtection = ['REDACTED FOR PRIVACY', 'PRIVACY PROTECTION', 'WHOISGUARD', 'PROXY'].some(k => json.includes(k));

  return {
    domain: domain,
    registrationDate: normalizeDate(registrationDate),
    expirationDate: normalizeDate(expirationDate),
    lastChangedDate: null,
    registrar,
    registrant: null,
    email: null,
    phone: null,
    status: (Array.isArray(data.status) ? data.status[0] : data.status) || null,
    privacyProtection,
    raw: data
  };
}

/**
 * 核心：查询域名 WHOIS 信息（天行优先，RDAP 兜底）
 * @returns {Promise<Object|null>}
 */
async function queryWhois(domain) {
  const tian = await queryWhoisTianApi(domain);
  if (tian) return tian;

  const rdap = await queryWhoisRdap(domain);
  if (rdap) return rdap;

  return null;
}

/**
 * 计算域名年龄相关信息
 * @param {string} registrationDate ISO 日期字符串
 * @returns {Object} { ageDays, ageText, isNew }
 */
function computeDomainAge(registrationDate) {
  if (!registrationDate) {
    return { ageDays: null, ageText: '未知', isNew: false, isExpiringSoon: false };
  }
  const regDate = new Date(registrationDate);
  const now = new Date();
  const ageMs = now.getTime() - regDate.getTime();
  const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));

  // 计算年龄文本
  let ageText;
  if (ageDays < 0) {
    ageText = '注册时间异常';
  } else if (ageDays < 1) {
    ageText = '注册于今日';
  } else if (ageDays < 30) {
    ageText = `${ageDays} 天`;
  } else if (ageDays < 365) {
    ageText = `${Math.floor(ageDays / 30)} 个月`;
  } else {
    const years = Math.floor(ageDays / 365);
    const remainMonths = Math.floor((ageDays % 365) / 30);
    ageText = remainMonths > 0 ? `${years} 年 ${remainMonths} 个月` : `${years} 年`;
  }

  return {
    ageDays,
    ageText,
    isNew: ageDays < 90,  // 新域名（<90天）标红
    registrationDate
  };
}

/**
 * 判断域名是否即将过期
 * @param {string} expirationDate ISO 日期字符串
 */
function computeExpirationStatus(expirationDate) {
  if (!expirationDate) {
    return { expiringSoon: false, expired: false, daysLeft: null };
  }
  const expDate = new Date(expirationDate);
  const now = new Date();
  const daysLeft = Math.floor((expDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  return {
    expiringSoon: daysLeft >= 0 && daysLeft < 30,  // 即将过期（<30天）
    expired: daysLeft < 0,
    daysLeft,
    expirationDate
  };
}
