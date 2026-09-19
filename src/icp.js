// ============================================================
// SiteGuard - ICP 备案查询模块
// 主数据源：天行数据 TianAPI（https://apis.tianapi.com/icp/index）
// 兜底：vvhan 免费接口（https://api.vvhan.com/api/icp）
// ============================================================

const TIANAPI_ICP_KEY = 'cb3e5ac6c0c94733bb638aeb09bae351';
const TIANAPI_ICP_URL = 'https://apis.tianapi.com/icp/index';

/**
 * 解析天行数据 ICP 接口返回的 result 字段为统一结构
 * 天行返回示例：
 *   { domain, icp_name, icp_type, icp_state, main_name, icp_number, update_time }
 *   icp_state: "存在" / "暂无"
 */
function parseTianApiIcpResult(r) {
  if (!r) return null;
  let hasIcp = null;
  if (r.icp_state === '存在') hasIcp = true;
  else if (r.icp_state === '暂无') hasIcp = false;

  return {
    hasIcp,
    icpNumber: r.icp_number || null,
    subject: r.main_name || null,     // 备案主体名称
    icpName: r.icp_name || null,      // 备案名称
    nature: r.icp_type || null,       // 主体类型（企业/个人/政府机关等）
    updateTime: r.update_time || null,
    raw: r
  };
}

/**
 * 天行数据 ICP 查询（主数据源）
 * @returns {Promise<Object|null>} 查询失败（网络错误/额度不足/数据为空）返回 null
 */
async function queryIcpTianApi(domain) {
  const url = `${TIANAPI_ICP_URL}?key=${encodeURIComponent(TIANAPI_ICP_KEY)}&domain=${encodeURIComponent(domain)}`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const resp = await fetch(url, { signal: controller.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data = await resp.json();
    if (data.code !== 200 || !data.result) {
      console.warn(`[SiteGuard] 天行 ICP 异常: ${domain} code=${data.code} msg=${data.msg}`);
      return null;
    }
    return parseTianApiIcpResult(data.result);
  } catch (err) {
    console.warn(`[SiteGuard] 天行 ICP 查询失败: ${domain}`, err.message);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * vvhan ICP 查询（兜底，免费无需 key）
 * @returns {Promise<Object|null>}
 */
async function queryIcpVvhan(domain) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  try {
    const url = `https://api.vvhan.com/api/icp?url=${encodeURIComponent(domain)}`;
    const resp = await fetch(url, { signal: controller.signal });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

    const data = await resp.json();
    // vvhan 返回格式：{ success: true, info: { name, nature, icp, ... } }
    if (data.success && data.info) {
      const info = data.info;
      const hasIcp = !!(info.icp && info.icp !== '未备案' && info.icp !== '');
      return {
        hasIcp,
        icpNumber: info.icp || null,
        subject: info.name || null,
        icpName: null,
        nature: info.nature || null,
        updateTime: null,
        raw: info
      };
    }
    // 未备案
    return {
      hasIcp: false,
      icpNumber: null,
      subject: null,
      icpName: null,
      nature: null,
      updateTime: null,
      raw: data
    };
  } catch (err) {
    console.warn(`[SiteGuard] vvhan ICP 查询失败: ${domain}`, err.message);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * 查询 ICP 备案信息（天行优先，vvhan 兜底）
 * @param {string} domain 主域名
 * @returns {Promise<Object>} { hasIcp, icpNumber, subject, icpName, nature, updateTime }
 *   hasIcp: true=已备案 | false=未备案 | null=未知（两个数据源都失败）
 */
async function queryIcp(domain) {
  const tian = await queryIcpTianApi(domain);
  if (tian) return tian;

  const vvhan = await queryIcpVvhan(domain);
  if (vvhan) return vvhan;

  return {
    hasIcp: null,
    icpNumber: null,
    subject: null,
    icpName: null,
    nature: null,
    updateTime: null,
    error: '查询失败'
  };
}

/**
 * 主体一致性校验
 * 将备案主体名称与官方域名池中的机构名称比对
 * @param {string|null} icpSubject 备案主体名称
 * @param {string|null} officialName 官方域名池中的机构名称
 * @returns {Object} { match: boolean|null, matchedName }
 */
function checkSubjectConsistency(icpSubject, officialName) {
  if (!icpSubject || !officialName) return { match: null };

  // 归一化：去空格、去公司后缀等常见变体
  const norm = (s) => s
    .replace(/\s+/g, '')
    .replace(/股份有限公司|有限责任公司|有限公司|集团|公司$/g, '');

  const a = norm(icpSubject);
  const b = norm(officialName);

  // 完全相等 或 互相包含
  const match = a === b || a.includes(b) || b.includes(a);
  return { match, matchedName: officialName };
}
