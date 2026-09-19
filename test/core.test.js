// ============================================================
// SiteGuard - 核心逻辑单元测试（Node 环境运行，不依赖浏览器 API）
// 运行：node test/core.test.js
// ============================================================

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ---------- 加载非浏览器依赖的模块 ----------
const SRC = path.join(__dirname, '..', 'src');

function loadModule(file, sandbox = {}) {
  const code = fs.readFileSync(path.join(SRC, file), 'utf8');
  // 补充浏览器环境全局对象（vm 沙箱默认没有 URL）
  sandbox.URL = URL;
  sandbox.console = console;
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  return sandbox;
}

// domain-utils（无依赖）
const du = loadModule('domain-utils.js');

// official-domain-pool（依赖 domain-utils 的 normalizeDomain）
const poolSandbox = {};
loadModule('domain-utils.js', poolSandbox);
loadModule('official-domain-pool.js', poolSandbox);

// scoring（在浏览器里靠 manifest 的 background.scripts 共享全局作用域，
// 这里同样把依赖模块加载进同一个沙箱）
const scoreSandbox = {};
loadModule('domain-utils.js', scoreSandbox);
loadModule('official-domain-pool.js', scoreSandbox);
loadModule('whois.js', scoreSandbox);
loadModule('icp.js', scoreSandbox);
loadModule('scoring.js', scoreSandbox);

let passed = 0, failed = 0;
function assert(cond, name) {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.error(`  ✗ ${name}`); }
}

// ---------- 测试 domain-utils ----------
console.log('\n[domain-utils]');
assert(du.getRegistrableDomain('login.people.com.cn') === 'people.com.cn',
  'getRegistrableDomain: login.people.com.cn -> people.com.cn');
assert(du.getRegistrableDomain('www.baidu.com') === 'baidu.com',
  'getRegistrableDomain: www.baidu.com -> baidu.com');
assert(du.getRegistrableDomain('icbc.com.cn') === 'icbc.com.cn',
  'getRegistrableDomain: icbc.com.cn -> icbc.com.cn');
assert(du.extractHostname('https://example.com/path?q=1#hash') === 'example.com',
  'extractHostname: 带 path/query/hash');
assert(du.getMainDomain('https://login.taobao.com/member/login.jhtml') === 'taobao.com',
  'getMainDomain: 完整 URL');
assert(du.isIPAddress('192.168.1.1') === true, 'isIPAddress: IPv4');
assert(du.isIPAddress('example.com') === false, 'isIPAddress: 域名');

// ---------- 测试官方域名池 ----------
console.log('\n[official-domain-pool]');
const official1 = poolSandbox.analyzeOfficialDomain('people.com.cn');
assert(official1.status === 'official' && official1.officialName === '人民网',
  '官方域名精确匹配: people.com.cn -> 人民网');

const official2 = poolSandbox.analyzeOfficialDomain('www.icbc.com.cn');
assert(official2.status === 'official' && official2.officialName === '中国工商银行',
  '子域名归属官方: www.icbc.com.cn -> 中国工商银行');

// 疑似仿冒检测：peop1e.com.cn vs people.com.cn（1 换 l）
const suspicious = poolSandbox.analyzeOfficialDomain('peop1e.com.cn');
assert(suspicious.status === 'suspicious' && suspicious.similarDomain === 'people.com.cn',
  `拼写混淆检测: peop1e.com.cn -> ${suspicious.status}/${suspicious.similarDomain || 'n/a'}`);

// 正常非官方不误报
const normal = poolSandbox.analyzeOfficialDomain('some-random-new-site.net');
assert(normal.status === 'unofficial', '普通非官方域名不误报');

// 同形字检测（西里尔 a 替换拉丁 a）
const homograph = poolSandbox.analyzeOfficialDomain('аpple.com'.replace('а', '\u0430'));
assert(homograph.status === 'suspicious' && homograph.homographAttack === true,
  '同形字攻击检测: 西里尔 а + pple.com');

// ---------- 测试后缀 Trie 匹配 ----------
console.log('\n[后缀 Trie]');
// 子域名归属（最长匹配）：login.weixin.qq.com -> weixin.qq.com（腾讯微信，更具体条目）
const trieSub = poolSandbox.lookupOfficialDomain('login.weixin.qq.com');
assert(trieSub.isOfficial === true && trieSub.officialName === '腾讯微信' && trieSub.matchedDomain === 'weixin.qq.com',
  '子域名归属: login.weixin.qq.com -> weixin.qq.com（腾讯微信）');

// 子域名归属：foo.people.com.cn -> people.com.cn（人民网）
const triePeople = poolSandbox.lookupOfficialDomain('foo.people.com.cn');
assert(triePeople.isOfficial === true && triePeople.matchedDomain === 'people.com.cn',
  '子域名归属: foo.people.com.cn -> people.com.cn');

// 标签边界：myqq.com 不应被误判为 qq.com 的子域名
const trieBoundary = poolSandbox.lookupOfficialDomain('myqq.com');
assert(trieBoundary.isOfficial === false,
  '标签边界: myqq.com 不误判为 qq.com 子域名');

// 宽后缀：beijing.gov.cn -> gov.cn（政府）
const trieGov = poolSandbox.lookupOfficialDomain('beijing.gov.cn');
assert(trieGov.isOfficial === true && trieGov.matchedDomain === 'gov.cn',
  '宽后缀: beijing.gov.cn -> gov.cn（政府）');

// 综合入口：子域名归属经 analyzeOfficialDomain 也成立
const subDomain = poolSandbox.analyzeOfficialDomain('foo.people.com.cn');
assert(subDomain.status === 'official' && subDomain.officialName === '人民网',
  'analyzeOfficialDomain 子域名: foo.people.com.cn -> 人民网');

// ---------- 测试评分引擎 ----------
console.log('\n[scoring]');

// 场景 1：官方站点，已备案主体一致，域名老，注册商合规 -> 高分
const goodSite = scoreSandbox.computeSecurityScore({
  domain: 'people.com.cn',
  whois: {
    registrationDate: '2000-01-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    registrar: 'Alibaba Cloud Computing'
  },
  icp: { hasIcp: true, icpNumber: '京ICP备030173号', subject: '人民网股份有限公司' },
  official: { status: 'official', officialName: '人民网' }
});
assert(goodSite.total >= 80 && goodSite.level === '安全',
  `官方+备案一致+域名老 => ${goodSite.total} 分（${goodSite.level}）`);

// 场景 2：新注册 + 未备案 + 非官方 -> 低分
const badSite = scoreSandbox.computeSecurityScore({
  domain: 'foo-bar-xyz123.top',
  whois: {
    registrationDate: new Date(Date.now() - 7 * 86400000).toISOString(),
    expirationDate: null,
    registrar: 'NameSilo'
  },
  icp: { hasIcp: false },
  official: { status: 'unofficial' }
});
assert(badSite.total < 60 && badSite.level === '高风险',
  `新域名+未备案+非官方 => ${badSite.total} 分（${badSite.level}）`);

// 场景 3：疑似仿冒 -> 应被显著扣分
const phishSite = scoreSandbox.computeSecurityScore({
  domain: 'peop1e.com.cn',
  whois: {
    registrationDate: new Date(Date.now() - 10 * 86400000).toISOString(),
    expirationDate: null,
    registrar: '未知'
  },
  icp: { hasIcp: false },
  official: { status: 'suspicious', similarDomain: 'people.com.cn', similarity: 0.86 }
});
assert(phishSite.total < 60,
  `疑似仿冒+新域名+未备案 => ${phishSite.total} 分（高风险）`);

// 场景 4：数据全部未知（查询失败）-> 应显示"未知"灰色状态而不是误报高风险
const unknownSite = scoreSandbox.computeSecurityScore({
  domain: 'unknown-example.org',
  whois: null,
  icp: { hasIcp: null },
  official: { status: 'unofficial' }
});
assert(unknownSite.total === null && unknownSite.level === '未知' && unknownSite.color === 'gray',
  `数据全未知 => ${unknownSite.total}（${unknownSite.level}，灰色问号）`);

// 场景 5：只有部分数据（ICP 成功但 WHOIS 失败）-> 正常评分，不进未知状态
const partialSite = scoreSandbox.computeSecurityScore({
  domain: 'some-icp-site.com',
  whois: null,
  icp: { hasIcp: true, icpNumber: '京ICP备12345678号', subject: '某某科技有限公司' },
  official: { status: 'unofficial' }
});
assert(partialSite.total !== null && partialSite.total > 0,
  `部分数据（已备案）=> ${partialSite.total} 分（正常评分）`);

// ---------- 测试 whois 日期归一化与隐私检测 ----------
console.log('\n[whois 解析]');
assert(scoreSandbox.normalizeDate('2000-09-28 00:00:00') === '2000-09-28T00:00:00.000Z',
  '天行实际格式（空格分隔、北京时间）归一化');
assert(scoreSandbox.normalizeDate('2016-06-28 T08:48:10Z') === '2016-06-28T00:00:00.000Z',
  '天行文档示例格式（带空格T）归一化');
assert(scoreSandbox.normalizeDate('2021-06-28T08:48:10Z') === '2021-06-28T00:00:00.000Z',
  '标准 ISO 日期归一化');
assert(scoreSandbox.normalizeDate('') === null && scoreSandbox.normalizeDate(null) === null,
  '空日期返回 null');
assert(scoreSandbox.detectPrivacy('juneker01', 'DomainAbuse@service.aliyun.com') === false,
  '正常注册人不判为隐私保护');
assert(scoreSandbox.detectPrivacy('REDACTED FOR PRIVACY', null) === true,
  'REDACTED FOR PRIVACY 判为隐私保护');

// ---------- 测试 ICP 解析（天行接口） ----------
console.log('\n[icp 解析]');
const icpParsed = scoreSandbox.parseTianApiIcpResult({
  domain: 'baidu.com',
  icp_name: '百度',
  icp_type: '企业',
  icp_state: '存在',
  main_name: '北京百度网讯科技有限公司',
  icp_number: '京ICP证030173号-1',
  update_time: '2019-05-21'
});
assert(icpParsed.hasIcp === true && icpParsed.subject === '北京百度网讯科技有限公司',
  '天行 ICP 已备案解析（主体名称）');
assert(icpParsed.icpNumber === '京ICP证030173号-1' && icpParsed.nature === '企业',
  '天行 ICP 备案号与主体类型');
assert(scoreSandbox.parseTianApiIcpResult({ icp_state: '暂无' }).hasIcp === false,
  '天行 ICP 状态"暂无" -> 未备案');
assert(scoreSandbox.parseTianApiIcpResult(null) === null,
  '空 result 返回 null');

// ---------- 输出结果 ----------
console.log(`\n测试结果: ${passed} 通过, ${failed} 失败`);
process.exit(failed > 0 ? 1 : 0);
