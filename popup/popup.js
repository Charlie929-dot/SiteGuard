// ============================================================
// SiteGuard - Popup 悬浮卡片逻辑
// 负责：获取当前标签页 URL，请求分析结果，渲染 UI
// ============================================================

//映射分数到100分制
function mapping(score) {
  return (score/10)*100;
}

/**
 * 格式化日期（YYYY-MM-DD）
 */
function formatDate(dateStr) {
  if (!dateStr) return '未知';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * 获取当前标签页 URL
 * 用回调风格调用（Chrome / Firefox 的 chrome 命名空间均支持），
 * 兼容 MV2 下 chrome.tabs.query 不返回 Promise 的情况
 */
function getCurrentTabUrl() {
  return new Promise((resolve) => {
    const queryInfo = { active: true, currentWindow: true };
    let settled = false;
    const finish = (url) => {
      if (!settled) { settled = true; resolve(url || null); }
    };

    const onResult = (tabs) => {
      if (chrome.runtime && chrome.runtime.lastError) {
        console.error('[SiteGuard] tabs.query:', chrome.runtime.lastError.message);
        finish(null);
        return;
      }
      if (tabs && tabs.length > 0) {
        finish(tabs[0].url || tabs[0].pendingUrl || null);
      } else {
        finish(null);
      }
    };

    if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
      console.error('[SiteGuard] 扩展 API 不可用（请通过浏览器扩展加载）');
      finish(null);
      return;
    }

    try {
      const ret = chrome.tabs.query(queryInfo, onResult);
      // 若实现返回 Promise（如新版 Chrome），用其结果兜底
      if (ret && typeof ret.then === 'function') {
        ret.then(onResult).catch((e) => { console.error('[SiteGuard] tabs.query:', e); finish(null); });
      }
    } catch (e) {
      console.error('[SiteGuard] 获取标签页失败', e);
      finish(null);
    }
  });
}

/**
 * 发送消息到后台（回调风格，兼容 MV2）
 */
function sendMessage(msg) {
  return new Promise((resolve, reject) => {
    try {
      chrome.runtime.sendMessage(msg, (response) => {
        if (chrome.runtime && chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response);
      });
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * 渲染顶部评分区域
 */
function renderScore(score) {
  const iconEl = document.getElementById('scoreIcon');
  const valueEl = document.getElementById('scoreValue');
  const levelEl = document.getElementById('scoreLevel');

  if (!score) {
    iconEl.textContent = '⚪';
    valueEl.textContent = '--';
    valueEl.className = 'score-value gray';
    levelEl.textContent = '未知';
    levelEl.className = 'score-level gray';
    return;
  }

  if (score.total === null) {
    // 数据不足，未知状态
    iconEl.textContent = score.icon || '❓';
    valueEl.textContent = '--';
    valueEl.className = 'score-value gray';
    levelEl.textContent = score.level || '未知';
    levelEl.className = 'score-level gray';
    return;
  }

  iconEl.textContent = score.icon;
  valueEl.textContent = score.total;
  valueEl.className = `score-value ${score.color}`;
  levelEl.textContent = score.level;
  levelEl.className = `score-level ${score.color}`;
}

/**
 * 渲染域名基础信息
 */
function renderWhois(whois, age, expiration) {
  document.getElementById('regTime').textContent = whois && whois.registrationDate
    ? formatDate(whois.registrationDate) : '未知';
  document.getElementById('regTime').className = 'value' + (age.isNew ? ' highlight-red' : '');

  const ageEl = document.getElementById('regAge');
  ageEl.textContent = age.ageText;
  ageEl.className = 'value' + (age.isNew ? ' highlight-red' : '');

  const expEl = document.getElementById('expTime');
  if (expiration.expiringSoon) {
    expEl.textContent = formatDate(expiration.expirationDate) + '（即将过期）';
    expEl.className = 'value highlight-yellow';
  } else if (expiration.expired) {
    expEl.textContent = formatDate(expiration.expirationDate) + '（已过期）';
    expEl.className = 'value highlight-red';
  } else {
    expEl.textContent = formatDate(expiration.expirationDate);
    expEl.className = 'value';
  }

  document.getElementById('registrar').textContent = whois ? whois.registrar : '未知';
  document.getElementById('privacy').textContent = whois && whois.privacyProtection ? '已启用' : '未启用';
}

/**
 * 渲染官方域名比对
 */
function renderOfficial(official) {
  const statusEl = document.getElementById('officialStatus');
  const nameRow = document.getElementById('officialNameRow');
  const nameEl = document.getElementById('officialName');
  const similarRow = document.getElementById('similarRow');
  const similarEl = document.getElementById('similarDomain');

  nameRow.style.display = 'none';
  similarRow.style.display = 'none';

  if (official.status === 'official') {
    statusEl.textContent = '✓ 官方站点';
    statusEl.className = 'value highlight-green';
    nameRow.style.display = 'flex';
    nameEl.textContent = official.officialName || '未知机构';
  } else if (official.status === 'suspicious') {
    statusEl.textContent = '⚠ 疑似仿冒';
    statusEl.className = 'value highlight-red';
    similarRow.style.display = 'flex';
    similarEl.textContent = `${official.similarDomain || ''}（相似度 ${Math.round((official.similarity || 0) * 100)}%）`;
    similarEl.className = 'value highlight-red';
  } else {
    statusEl.textContent = '非官方/未知';
    statusEl.className = 'value highlight-yellow';
  }
}

/**
 * 渲染 ICP 备案
 */
function renderIcp(icp) {
  const statusEl = document.getElementById('icpStatus');
  const numberRow = document.getElementById('icpNumberRow');
  const numberEl = document.getElementById('icpNumber');
  const subjectRow = document.getElementById('icpSubjectRow');
  const subjectEl = document.getElementById('icpSubject');

  numberRow.style.display = 'none';
  subjectRow.style.display = 'none';

  if (icp.hasIcp === null) {
    statusEl.textContent = '查询失败/未知';
    statusEl.className = 'value';
  } else if (icp.hasIcp) {
    statusEl.textContent = '✓ 已备案';
    statusEl.className = 'value highlight-green';
    if (icp.icpNumber) {
      numberRow.style.display = 'flex';
      numberEl.textContent = icp.icpNumber;
    }
    if (icp.subject) {
      subjectRow.style.display = 'flex';
      subjectEl.textContent = icp.subject;
    }
  } else {
    statusEl.textContent = '✗ 未备案';
    statusEl.className = 'value highlight-red';
  }
}

/**
 * 渲染评分明细
 */
function renderFactors(factors) {
  const factorSection = document.getElementById('factorSection');
  const factorList = document.getElementById('factorList');

  if (!factors || factors.length === 0) {
    factorSection.style.display = 'none';
    return;
  }

  factorSection.style.display = 'block';
  factorList.innerHTML = '';

  for (const f of factors) {
    const item = document.createElement('div');
    item.className = 'factor-item';

    const row = document.createElement('div');
    row.className = 'factor-row';

    const name = document.createElement('span');
    name.className = 'factor-name';
    name.textContent = f.name;

    const score = document.createElement('span');
    const scoreClass = f.score > 0 ? 'positive' : (f.score < 0 ? 'negative' : 'neutral');
    score.className = `factor-score ${scoreClass}`;
    score.textContent = `${Math.max(0, Math.min(100, mapping(f.score)))}%`;

    row.appendChild(name);
    row.appendChild(score);

    // 进度条（映射 0-10 到 0-100%）
    const bar = document.createElement('div');
    bar.className = 'factor-bar';
    const fill = document.createElement('div');
    const pct = mapping(f.score);
    fill.className = `factor-bar-fill ${scoreClass}`;
    fill.style.width = `${pct}%`;
    bar.appendChild(fill);

    const label = document.createElement('div');
    label.className = 'factor-label';
    label.textContent = f.label;

    item.appendChild(row);
    item.appendChild(bar);
    item.appendChild(label);
    factorList.appendChild(item);
  }
}

/**
 * 渲染风险警告框
 */
function renderWarning(analysis) {
  const warningBox = document.getElementById('warningBox');
  const risks = [];

  if (analysis.score.total !== null && analysis.score.total < 60) {
    if (analysis.official.status === 'suspicious') {
      risks.push(`疑似仿冒官方域名「${analysis.official.similarDomain}」`);
    }
    if (analysis.whois && analysis.whois.registrationDate) {
      if (analysis.score.age.isNew) {
        risks.push(`域名注册仅 ${analysis.score.age.ageText}`);
      }
    }
    if (analysis.icp.hasIcp === false) {
      risks.push('未查询到 ICP 备案信息');
    }
    if (analysis.official.status === 'unofficial') {
      risks.push('不在官方域名池中');
    }
    if (analysis.whois && analysis.score.expiration.expired) {
      risks.push('域名已过期');
    }
  }

  if (risks.length === 0) {
    warningBox.style.display = 'none';
    return;
  }

  warningBox.style.display = 'block';
  warningBox.innerHTML = `
    <div class="warning-title">⚠️ 风险提示</div>
    <ul>
      ${risks.map(r => `<li>${r}</li>`).join('')}
    </ul>
  `;
}

/**
 * 渲染未知/无效域名状态
 */
function renderInvalid(reason) {
  document.getElementById('domain').textContent = reason || '无法识别域名';
  renderScore(null);
  document.getElementById('factorSection').style.display = 'none';
  document.getElementById('whoisList').innerHTML = '<div class="loading">非 HTTP(S) 页面或 IP 地址，暂不分析</div>';
  document.getElementById('officialList').innerHTML = '';
  document.getElementById('icpList').innerHTML = '';
}

/**
 * 主流程
 */
async function main() {
  let url = await getCurrentTabUrl();
  if (!url) {
    // 兜底：直接查询失败时，从后台取活动标签页 URL
    try {
      const resp = await sendMessage({ type: 'GET_ACTIVE_TAB' });
      url = resp && resp.url ? resp.url : null;
    } catch (e) {
      console.error('[SiteGuard] 兜底获取 URL 失败', e);
    }
  }
  if (!url) {
    renderInvalid('无法获取当前页面（可能是浏览器内部页，或无 URL 权限）');
    return;
  }

  // 提取主域名用于展示
  const mainDomain = url.match(/^https?:\/\/([^/]+)/i);
  if (mainDomain) {
    document.getElementById('domain').textContent = mainDomain[1];
  }

  // 请求后台分析
  try {
    const response = await sendMessage({ type: 'ANALYZE_URL', url });
    if (!response.success) {
      renderInvalid('分析失败：' + (response.error || '未知错误'));
      return;
    }

    const analysis = response.analysis;
    if (!analysis || !analysis.domain) {
      renderInvalid('非 HTTP(S) 页面或 IP 地址');
      return;
    }

    renderScore(analysis.score);
    renderWhois(analysis.whois, analysis.score.age, analysis.score.expiration);
    renderOfficial(analysis.official);
    renderIcp(analysis.icp);
    renderFactors(analysis.score.factors);
    renderWarning(analysis);
  } catch (err) {
    renderInvalid('分析出错：' + err.message);
  }
}

document.addEventListener('DOMContentLoaded', main);

// 清除缓存按钮：向后台发送 CLEAR_CACHE 消息，清空已缓存的分析结果
const clearCacheBtn = document.getElementById('clearCacheBtn');
if (clearCacheBtn) {
  clearCacheBtn.addEventListener('click', async () => {
    const original = clearCacheBtn.textContent;
    clearCacheBtn.disabled = true;
    clearCacheBtn.textContent = '清除中...';
    try {
      const resp = await sendMessage({ type: 'CLEAR_CACHE' });
      clearCacheBtn.textContent = (resp && resp.success) ? '已清除 ✓' : '清除失败';
    } catch (e) {
      clearCacheBtn.textContent = '清除失败';
    }
    setTimeout(() => {
      clearCacheBtn.textContent = original;
      clearCacheBtn.disabled = false;
    }, 2000);
  });
}
