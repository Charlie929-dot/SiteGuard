// ============================================================
// SiteGuard - 官方域名池模块
// 负责：维护官方域名资产库，比对用户访问域名是否官方/疑似仿冒/非官方
// ============================================================

// 初始官方域名池种子数据（MVP 阶段内置）
// 结构：{ "域名": "机构名称" }
// 数据来源：政府 .gov.cn、高校 .edu.cn、知名企业官网
const OFFICIAL_DOMAIN_SEEDS = {
  // ===== 政府机构 =====
  'gov.cn': '中华人民共和国中央人民政府',
  'beian.miit.gov.cn': '工业和信息化部',
  'people.com.cn': '人民网',
  'xinhuanet.com': '新华网',
  'cctv.com': '央视网',
  'cctv.cn': '央视网',
  'cntv.cn': '央视网',
  'chinanews.com.cn': '中国新闻网',
  'chinadaily.com.cn': '中国日报网',
  'gmw.cn': '光明网',
  'youth.cn': '中国青年网',
  'cnr.cn': '央广网',
  'china.com.cn': '中国网',
  'ce.cn': '中国经济网',
  'cnstock.com': '中国证券网',
  'cs.com.cn': '中证网',

  // ===== 高校 =====
  'tsinghua.edu.cn': '清华大学',
  'pku.edu.cn': '北京大学',
  'fudan.edu.cn': '复旦大学',
  'sjtu.edu.cn': '上海交通大学',
  'zju.edu.cn': '浙江大学',
  'nju.edu.cn': '南京大学',
  'ustc.edu.cn': '中国科学技术大学',
  'whu.edu.cn': '武汉大学',
  'hust.edu.cn': '华中科技大学',
  'xjtu.edu.cn': '西安交通大学',
  'scu.edu.cn': '四川大学',
  'sysu.edu.cn': '中山大学',
  'ruc.edu.cn': '中国人民大学',
  'bupt.edu.cn': '北京邮电大学',

  // ===== 互联网/科技企业 =====
  'baidu.com': '百度',
  'qq.com': '腾讯',
  'tencent.com': '腾讯',
  'weixin.qq.com': '腾讯微信',
  'alibaba.com': '阿里巴巴',
  'taobao.com': '淘宝',
  'tmall.com': '天猫',
  'jd.com': '京东',
  'meituan.com': '美团',
  'dianping.com': '大众点评',
  'bytedance.com': '字节跳动',
  'douyin.com': '抖音',
  'toutiao.com': '今日头条',
  'xiaohongshu.com': '小红书',
  '163.com': '网易',
  'netease.com': '网易',
  'sina.com.cn': '新浪',
  'weibo.com': '微博',
  'sohu.com': '搜狐',
  '360.cn': '奇虎360',
  'bilibili.com': '哔哩哔哩',
  'kuaishou.com': '快手',
  'pinduoduo.com': '拼多多',
  'vip.com': '唯品会',
  'suning.com': '苏宁易购',
  'zhihu.com': '知乎',
  'iqiyi.com': '爱奇艺',
  'youku.com': '优酷',
  'douban.com': '豆瓣',
  'ctrip.com': '携程',
  'qunar.com': '去哪儿',
  'trip.com': '携程集团',

  // ===== 金融 =====
  'icbc.com.cn': '中国工商银行',
  'ccb.com': '中国建设银行',
  'abchina.com': '中国农业银行',
  'boc.cn': '中国银行',
  'bankcomm.com': '交通银行',
  'cmbchina.com': '招商银行',
  'spdb.com.cn': '浦发银行',
  'citicbank.com': '中信银行',
  'cebbank.com': '光大银行',
  'cgbchina.com.cn': '广发银行',
  'hxb.com.cn': '华夏银行',
  'pingan.com': '中国平安',
  'alipay.com': '支付宝',
  'paypal.com': 'PayPal',
  'unionpay.com': '中国银联',
  'julongbao.com': '支付平台',

  // ===== 运营商 =====
  '10086.cn': '中国移动',
  'chinamobile.com': '中国移动',
  '189.cn': '中国电信',
  'chinatelecom.com.cn': '中国电信',
  '10010.com': '中国联通',
  'chinaunicom.com.cn': '中国联通',

  // ===== 国际知名网站 =====
  'google.com': 'Google',
  'youtube.com': 'YouTube',
  'facebook.com': 'Facebook',
  'twitter.com': 'Twitter/X',
  'x.com': 'Twitter/X',
  'instagram.com': 'Instagram',
  'linkedin.com': 'LinkedIn',
  'amazon.com': 'Amazon',
  'microsoft.com': 'Microsoft',
  'apple.com': 'Apple',
  'github.com': 'GitHub',
  'gitlab.com': 'GitLab',
  'wikipedia.org': 'Wikipedia',
  'reddit.com': 'Reddit',
  'netflix.com': 'Netflix',
  'cloudflare.com': 'Cloudflare',
  'cloudflare.net': 'Cloudflare',
  'whatsapp.com': 'WhatsApp',
  'telegram.org': 'Telegram',
  'zoom.us': 'Zoom',
  'office.com': 'Microsoft Office',
  'azure.com': 'Microsoft Azure',
  'aws.amazon.com': 'Amazon Web Services'
};

// ============================================================
// 后缀 Trie（Suffix Trie）
// 用于高效判断某个域名是否为官方域名池中某条目的「后缀」（即子域名归属）
// 原理：把官方域名反转后插入 Trie；查询时反转 hostname 逐字符匹配，
//       取最长（最具体）的命中条目，并要求命中边界落在「标签」上（前一个是 '.'），
//       避免 myqq.com 被误判为 qq.com 的子域名
// ============================================================

class TrieNode {
  constructor() {
    this.children = {};   // 字符 -> TrieNode
    this.isEnd = false;   // 是否为某个官方域名的结尾
    this.name = null;     // 命中条目的机构名称
    this.domain = null;   // 命中条目的官方域名
  }
}

class SuffixTrie {
  constructor(seedMap) {
    this.root = new TrieNode();
    for (const domain of Object.keys(seedMap)) {
      this._insert(domain, seedMap[domain]);
    }
  }

  // 反转后插入
  _insert(domain, name) {
    const reversed = Array.from(domain).reverse();
    let node = this.root;
    for (const ch of reversed) {
      if (!node.children[ch]) node.children[ch] = new TrieNode();
      node = node.children[ch];
    }
    node.isEnd = true;
    node.name = name;
    node.domain = domain;
  }

  // 判断 text 是否以字典集中某个后缀结尾（对应参考实现的 has_suffix 语义）
  hasSuffix(text) {
    let node = this.root;
    for (const ch of Array.from(text).reverse()) {
      if (!node.children[ch]) return false;
      node = node.children[ch];
      if (node.isEnd) return true;
    }
    return false;
  }

  // 最长匹配：返回 text 结尾命中且标签边界正确的最具体条目
  // 返回 { domain, name } 或 null
  matchLongest(text) {
    const reversed = Array.from(text).reverse();
    let node = this.root;
    let best = null;
    for (let i = 0; i < reversed.length; i++) {
      const ch = reversed[i];
      if (!node.children[ch]) break;
      node = node.children[ch];
      if (node.isEnd) {
        // 标签边界校验：后缀要么是整串，要么其前一个字符是 '.'
        const isFull = (i === reversed.length - 1);
        const prev = reversed[i + 1];
        if (isFull || prev === '.') {
          best = node;
        }
      }
    }
    return best ? { domain: best.domain, name: best.name } : null;
  }
}

// 由种子数据一次性构建全局后缀 Trie
const officialSuffixTrie = new SuffixTrie(OFFICIAL_DOMAIN_SEEDS);

/**
 * Levenshtein 编辑距离算法
 * 检测拼写混淆（0 换 o、1 换 l、rn 换 m 等）
 */
function levenshteinDistance(a, b) {
  if (a === b) return 0;
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      const cost = a[j - 1] === b[i - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // 删除
        matrix[i][j - 1] + 1,      // 插入
        matrix[i - 1][j - 1] + cost // 替换
      );
    }
  }
  return matrix[b.length][a.length];
}

/**
 * 同形字规范化（IDN Homograph Attack 检测）
 * 将易混淆的 Unicode 字符映射到 ASCII 等价字符
 */
function normalizeHomograph(domain) {
  const map = {
    // 西里尔字母 -> 拉丁字母
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'т': 't',
    // 希腊字母
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't',
    // 全角字符
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e'
  };

  return domain.split('').map(ch => map[ch] || ch).join('');
}

/**
 * 查询域名是否在官方域名池中（使用后缀 Trie 做最长后缀匹配）
 * @param {string} hostname 主机名（如 login.weixin.qq.com、beijing.gov.cn）
 * @returns {Object} { isOfficial, officialName, matchedDomain }
 */
function lookupOfficialDomain(hostname) {
  const normalized = normalizeDomain(hostname);
  const match = officialSuffixTrie.matchLongest(normalized);

  if (match) {
    return {
      isOfficial: true,
      officialName: match.name,
      matchedDomain: match.domain
    };
  }

  return { isOfficial: false, officialName: null, matchedDomain: null };
}

/**
 * 检测疑似仿冒（相似域名）
 * 将目标域名与官方域名池中的所有域名做相似度比对
 * @param {string} domain 主域名
 * @returns {Object|null} { suspicious, similarDomain, distance, officialName }
 */
function detectSuspiciousSimilar(domain) {
  const normalized = normalizeDomain(domain);
  const homographNormalized = normalizeHomograph(normalized);
  const base = homographNormalized.split('.')[0]; // 只看 SLD 部分（如 people）

  let bestMatch = null;
  let bestDistance = Infinity;

  for (const officialDomain of Object.keys(OFFICIAL_DOMAIN_SEEDS)) {
    const officialBase = officialDomain.split('.')[0];
    // 长度差异过大则跳过（>3 基本不可能是混淆）
    if (Math.abs(officialBase.length - base.length) > 3) continue;

    const distance = levenshteinDistance(base, officialBase);

    // 相似度阈值：编辑距离 <= 2 且域名不相等
    if (distance <= 2 && distance > 0 && distance < bestDistance) {
      bestDistance = distance;
      bestMatch = {
        suspicious: true,
        similarDomain: officialDomain,
        distance,
        officialName: OFFICIAL_DOMAIN_SEEDS[officialDomain],
        similarity: 1 - distance / Math.max(base.length, officialBase.length)
      };
    }
    // 同形字攻击检测：规范化后完全相同但原始不同
    if (homographNormalized !== normalized && distance === 0) {
      return {
        suspicious: true,
        similarDomain: officialDomain,
        distance: 0,
        officialName: OFFICIAL_DOMAIN_SEEDS[officialDomain],
        similarity: 1,
        homographAttack: true
      };
    }
  }

  // 编辑距离为 1-2 才判定为"疑似仿冒"
  return bestMatch && bestMatch.distance <= 2 ? bestMatch : null;
}

/**
 * 综合官方域名池比对结果
 * @param {string} hostname 主机名（如 login.weixin.qq.com）
 */
function analyzeOfficialDomain(hostname) {
  // 1. 后缀 Trie 匹配：官方域名池精确命中 + 子域名归属（最长匹配）
  const lookup = lookupOfficialDomain(hostname);

  if (lookup.isOfficial) {
    return {
      status: 'official',           // official / suspicious / unofficial
      officialName: lookup.officialName,
      matchedDomain: lookup.matchedDomain
    };
  }

  // 2. 疑似仿冒检测：基于可注册域（eTLD+1）的 SLD 做相似度比对
  const registrable = getRegistrableDomain(normalizeDomain(hostname));
  const suspicious = detectSuspiciousSimilar(registrable);
  if (suspicious) {
    return {
      status: 'suspicious',
      officialName: suspicious.officialName,
      similarDomain: suspicious.similarDomain,
      distance: suspicious.distance,
      similarity: suspicious.similarity,
      homographAttack: suspicious.homographAttack || false
    };
  }

  return { status: 'unofficial' };
}

/**
 * 将种子数据导出（供 popup 展示、后续可能持久化到 storage）
 */
function getOfficialDomainCount() {
  return Object.keys(OFFICIAL_DOMAIN_SEEDS).length;
}
