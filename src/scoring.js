// ============================================================
// SiteGuard - 综合安全评分引擎
// 负责：基于官方域名池、ICP 备案、域名年龄、注册商等维度计算 0-100 安全评分
//
// 权重（来自策划案，Phase 1 阶段流量维度暂用占位）：
//   官方域名池匹配 30% | ICP 备案一致性 25% | 域名年龄 20%
//   流量热度 15%（Phase 2 接入）| 注册商信誉 10%
// ============================================================

// 高危注册商列表（已知被大量用于钓鱼/垃圾邮件的注册商）
const HIGH_RISK_REGISTRARS = [
  'namesilo', 'namecheap', 'gmo', 'onamae', 'porkbun',
  'nicenic', 'todaynic', 'dynadot', 'freenom', 'gandi',
  'west.cn', 'wanwang'  // 注意：这些并非绝对高危，MVP 阶段只做弱提示，需结合其他维度
];

// 合规大厂注册商（信誉加分）
const TRUSTED_REGISTRARS = [
  'alibaba', 'aliyun', 'godaddy', 'markmonitor', 'csc',
  'tucows', 'network solutions', 'china nic', 'cnnic',
  'verisign', 'google', 'amazon', 'cloudflare'
];

/**
 * 官方域名池维度评分（10 分）
 */
function scoreOfficialDomain(officialResult) {
  if (officialResult.status === 'official') return { score: 50, label: '官方站点' };
  if (officialResult.status === 'suspicious') return { score: -10, label: '疑似仿冒' };
  return { score: 5, label: '非官方/未知' };
}

/**
 * ICP 备案维度评分（10 分）
 * @param {Object} icpResult queryIcp 的返回
 * @param {Object} officialResult 官方域名池结果
 */
function scoreIcp(icpResult, officialResult) {
  if (icpResult.hasIcp === null) return { score: 0, label: '备案信息未知' };

  if (!icpResult.hasIcp) return { score: -10, label: '未备案' };

  // 已备案
  if (officialResult.status === 'official' && officialResult.officialName) {
    // 主体一致性校验
    const consistency = checkSubjectConsistency(icpResult.subject, officialResult.officialName);
    if (consistency.match === true) {
      return { score: 10, label: '已备案且主体一致' };
    }
    if (consistency.match === false) {
      return { score: 8, label: '已备案但主体不符' };
    }
  }
  return { score: 5, label: '已备案' };
}

/**
 * 域名年龄维度评分（10 分）
 * @param {Object} ageResult computeDomainAge 的返回
 */
function scoreAge(ageResult) {
  if (ageResult.ageDays === null) return { score: 0, label: '注册时间未知' };
  if (ageResult.ageDays < 90) return { score: -10, label: '新注册域名（<90天）' };
  if (ageResult.ageDays < 365) return { score: 3, label: '注册 3 个月 - 1 年' };
  if (ageResult.ageDays < 365 * 3) return { score: 5, label: '注册 1-3 年' };
  return { score: 10, label: '注册 >3 年' };
}

/**
 * 注册商信誉维度评分（10 分）
 * @param {string|null} registrar 注册商名称
 */
function scoreRegistrar(registrar) {
  if (!registrar || registrar === '未知') return { score: 0, label: '注册商未知' };

  const lower = registrar.toLowerCase();

  const trusted = TRUSTED_REGISTRARS.find(r => lower.includes(r));
  if (trusted) return { score: 10, label: '合规注册商' };

  const highRisk = HIGH_RISK_REGISTRARS.find(r => lower.includes(r));
  if (highRisk) return { score: -10, label: '注册商需留意' };

  return { score: 5, label: '注册商中性' };
}

/**
 * 综合安全评分
 * @param {Object} data { domain, whois, icp, official }
 * @returns {Object} { total, level, color, icon, details, factors }
 */
function computeSecurityScore(data) {
  const { whois, icp, official } = data;

  const ageResult = computeDomainAge(whois ? whois.registrationDate : null);

  const officialScore = scoreOfficialDomain(official);
  const icpScore = scoreIcp(icp, official);
  const ageScore = scoreAge(ageResult);
  const registrarScore = scoreRegistrar(whois ? whois.registrar : null);

  // 总分 = 各项得分直接相加（各维度满分 30+25+20+10=85，加上流量 15 = 100）
  // Phase 1 无流量数据，按比例折算到 100 分制
  const phase1Total = officialScore.score + icpScore.score + ageScore.score + registrarScore.score;
  // 满分 40，折算到  分制，total初始50分
  let total = 50 + Math.round((phase1Total / 40) * 50);

  // 额外风险扣分：域名过期 / 即将过期
  const expStatus = computeExpirationStatus(whois ? whois.expirationDate : null);
  if (expStatus.expired) total -= 10;
  else if (expStatus.expiringSoon) total -= 5;

  // 限制在 0-100
  total = Math.max(0, Math.min(100, total));

  const factors = [
    { name: '官方域名池', score: officialScore.score, max: 10, label: officialScore.label },
    { name: 'ICP 备案', score: icpScore.score, max: 10, label: icpScore.label },
    { name: '域名年龄', score: ageScore.score, max: 10, label: ageScore.label },
    { name: '注册商信誉', score: registrarScore.score, max: 10, label: registrarScore.label }
  ];

  // 判定等级
  let level, color, icon;

  // 特殊状态：所有数据源都查询失败（境外站/网络受限/非 .cn 且无 RDAP）时，
  // 显示"未知"（灰色问号）而不是误报高风险
  const allUnknown = (!whois && icp.hasIcp === null && official.status === 'unofficial');
  if (allUnknown) {
    return {
      total: null,
      level: '未知',
      color: 'gray',
      icon: '❓',
      age: ageResult,
      expiration: expStatus,
      factors
    };
  }

  if (total >= 80) {
    level = '安全';
    color = 'green';
    icon = '🟢';
  } else if (total >= 60) {
    level = '中等风险';
    color = 'yellow';
    icon = '🟡';
  } else {
    level = '高风险';
    color = 'red';
    icon = '🔴';
  }

  return {
    total,
    level,
    color,
    icon,
    age: ageResult,
    expiration: expStatus,
    factors
  };
}
