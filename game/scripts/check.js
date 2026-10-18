'use strict';

const { lookup } = require('node:dns/promises');
const { isIP } = require('node:net');

const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 512 * 1024;
const SYSTEM_PROMPT =
  'You are a fraud analyst. Find red flags: vague product, fake urgency, no team names, pay-to-join offers, unrealistic promises. Return ONLY JSON: {score: 0-100, flags: string[], summary: string}';

function ipv4ToNumber(address) {
  return address.split('.').map(Number).reduce((value, octet) => value * 256 + octet, 0) >>> 0;
}

function ipv6ToBigInt(address) {
  let normalized = address.toLowerCase();
  if (normalized.includes('.')) {
    const splitAt = normalized.lastIndexOf(':');
    const embedded = ipv4ToNumber(normalized.slice(splitAt + 1));
    normalized = `${normalized.slice(0, splitAt)}:${(embedded >>> 16).toString(16)}:${(embedded & 0xffff).toString(16)}`;
  }
  const halves = normalized.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 1
    ? left
    : [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
  if (groups.length !== 8) throw new Error('Invalid IPv6 address.');
  return groups.reduce((value, group) => (value << 16n) | BigInt(`0x${group || '0'}`), 0n);
}

function inRange(ip, network, prefix, version) {
  if (version === 4) {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (ipv4ToNumber(ip) & mask) === (ipv4ToNumber(network) & mask);
  }
  const shift = BigInt(128 - prefix);
  return (ipv6ToBigInt(ip) >> shift) === (ipv6ToBigInt(network) >> shift);
}

function isUnsafeIp(address) {
  const ip = address.replace(/^\[|\]$/g, '').split('%')[0];
  const version = isIP(ip);
  if (version === 4) {
    return [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10],
      ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
      ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24],
      ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
      ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
    ].some(([network, prefix]) => inRange(ip, network, prefix, 4));
  }
  if (version === 6) {
    const value = ipv6ToBigInt(ip);
    if ((value >> 32n) === 0xffffn) {
      const mapped = [24n, 16n, 8n, 0n]
        .map((shift) => Number((value >> shift) & 255n)).join('.');
      return isUnsafeIp(mapped);
    }
    return [
      ['::', 128], ['::1', 128], ['fc00::', 7],
      ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32],
    ].some(([network, prefix]) => inRange(ip, network, prefix, 6));
  }
  return false;
}

function hostname(url) {
  return url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

async function assertPublicUrl(url) {
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Only public HTTP or HTTPS URLs without credentials are allowed.');
  }
  const host = hostname(url);
  if (!host || host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Local and private website addresses are not allowed.');
  }
  if (isIP(host)) {
    if (isUnsafeIp(host)) throw new Error('Private, loopback, link-local, or reserved IP addresses are not allowed.');
    return;
  }
  const resolved = await lookup(host, { all: true, verbatim: true });
  if (!resolved.length || resolved.some(({ address }) => isUnsafeIp(address))) {
    throw new Error('The website resolves to a private, loopback, link-local, or reserved IP address.');
  }
}

function parseIssueUrl(body) {
  const match = String(body || '').match(
    /(?:^|\r?\n)###\s*Startup website URL\s*\r?\n([\s\S]*?)(?=\r?\n###\s|$)/i,
  );
  if (!match) throw new Error('Missing the required "Startup website URL" field.');
  const entries = match[1].split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (entries.length !== 1 || entries[0].length > 2048 || /[\s<>"'`]/.test(entries[0])) {
    throw new Error('Enter exactly one valid HTTP or HTTPS website URL.');
  }
  let url;
  try {
    url = new URL(entries[0]);
  } catch {
    throw new Error('The startup website URL is invalid.');
  }
  if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) {
    throw new Error('Only HTTP or HTTPS website URLs without credentials are allowed.');
  }
  return url;
}

async function withTimeout(task, label, milliseconds = TIMEOUT_MS) {
  const controller = new AbortController();
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error(`${label} timed out after ${milliseconds / 1000} seconds.`));
    }, milliseconds);
  });
  try {
    return await Promise.race([task(controller.signal), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

async function fetchPublic(input, options = {}, signal) {
  const { maxRedirects = MAX_REDIRECTS, ...fetchOptions } = options;
  let current = new URL(input);
  for (let redirects = 0; ; redirects += 1) {
    await assertPublicUrl(current);
    const response = await fetch(current, { ...fetchOptions, redirect: 'manual', signal });
    if (![301, 302, 303, 307, 308].includes(response.status)) return { response, url: current };
    const location = response.headers.get('location');
    await response.body?.cancel();
    if (!location || redirects >= maxRedirects || (fetchOptions.method && fetchOptions.method !== 'GET')) {
      throw new Error('The website returned an unsupported or excessive redirect.');
    }
    current = new URL(location, current);
  }
}

async function jsonResponse(response, source) {
  if (!response.ok) throw new Error(`${source} returned HTTP ${response.status}.`);
  return response.json();
}

function domainAgeScore(days) {
  if (days >= 1825) return 100;
  if (days >= 730) return 80;
  if (days >= 365) return 60;
  if (days >= 180) return 40;
  return 20;
}

async function checkDomainAge(url, signal) {
  const domain = hostname(url).replace(/^www\./, '');
  const endpoint = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  const { response } = await fetchPublic(endpoint, {}, signal);
  const data = await jsonResponse(response, 'RDAP');
  const event = Array.isArray(data.events) &&
    data.events.find((item) => /registration|registered/i.test(item.eventAction || '') && item.eventDate);
  const date = event && new Date(event.eventDate);
  if (!date || Number.isNaN(date.getTime()) || date.getTime() > Date.now()) {
    throw new Error('RDAP did not provide a valid domain registration date.');
  }
  const days = Math.floor((Date.now() - date.getTime()) / 86_400_000);
  return { score: domainAgeScore(days), detail: `Registered ${date.toISOString().slice(0, 10)} (${days} days ago).` };
}

function firstSnapshotDate(data) {
  if (!Array.isArray(data) || !Array.isArray(data[1])) return null;
  const timestamp = String(data[1][0] || '');
  if (!/^\d{14}$/.test(timestamp)) return null;
  const date = new Date(`${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}-${timestamp.slice(6, 8)}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

async function checkWayback(url, signal) {
  const domain = hostname(url);
  const availabilityUrl = new URL('https://archive.org/wayback/available');
  availabilityUrl.searchParams.set('url', domain);
  const cdxUrl = new URL('https://web.archive.org/cdx/search/cdx');
  for (const [key, value] of [
    ['url', domain], ['output', 'json'], ['fl', 'timestamp'],
    ['filter', 'statuscode:200'], ['collapse', 'urlkey'],
    ['sort', 'timestamp:asc'], ['limit', '1'],
  ]) cdxUrl.searchParams.set(key, value);

  const [availableResult, firstResult] = await Promise.allSettled([
    fetchPublic(availabilityUrl, {}, signal).then(({ response }) => jsonResponse(response, 'Wayback availability')),
    fetchPublic(cdxUrl, {}, signal).then(({ response }) => jsonResponse(response, 'Wayback CDX')),
  ]);
  const availability = availableResult.status === 'fulfilled' ? availableResult.value : null;
  const closest = availability?.archived_snapshots?.closest;
  const firstDate = firstResult.status === 'fulfilled' ? firstSnapshotDate(firstResult.value) : null;
  if (firstDate) {
    const days = Math.max(0, Math.floor((Date.now() - firstDate.getTime()) / 86_400_000));
    const score = days >= 1825 ? 100 : days >= 730 ? 80 : days >= 365 ? 60 : 40;
    return { score, detail: `First archived snapshot: ${firstDate.toISOString().slice(0, 10)} (${days} days ago).` };
  }
  if (closest?.available && closest.timestamp) {
    const date = /^\d{14}$/.test(String(closest.timestamp))
      ? `${closest.timestamp.slice(0, 4)}-${closest.timestamp.slice(4, 6)}-${closest.timestamp.slice(6, 8)}`
      : 'date unavailable';
    return { score: 50, detail: `A Wayback snapshot exists (${date}); the first snapshot date is unavailable.` };
  }
  if (availableResult.status === 'rejected' && firstResult.status === 'rejected') {
    throw new Error('Wayback availability and first-snapshot lookups both failed.');
  }
  return { score: 20, detail: 'No Wayback snapshots were found for this domain.' };
}

async function checkReachability(url, signal) {
  const { response, url: finalUrl } = await fetchPublic(url, {}, signal);
  await response.body?.cancel();
  const score = response.status >= 500 ? 20
    : finalUrl.protocol === 'https:' ? (response.status >= 400 ? 80 : 100)
      : (response.status >= 400 ? 35 : 55);
  return {
    score,
    detail: `Reached ${finalUrl.protocol}//${finalUrl.host} (HTTP ${response.status}; ${finalUrl.protocol === 'https:' ? 'HTTPS' : 'HTTP only'}).`,
  };
}

async function readLimitedText(response, maximum) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (size < maximum) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value.subarray(0, maximum - size);
      chunks.push(chunk);
      size += chunk.length;
      if (chunk.length < value.length) break;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(bytes);
}

function stripHtml(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|noscript|svg|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;|&#160;/gi, ' ')
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, ' ').trim().slice(0, 3000);
}

async function fetchHomepageText(url, signal) {
  const { response } = await fetchPublic(url, {
    headers: { accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1' },
  }, signal);
  const contentType = response.headers.get('content-type') || '';
  if (!response.ok || !/text\/html|application\/xhtml\+xml/i.test(contentType)) {
    await response.body?.cancel();
    throw new Error(!response.ok
      ? `Homepage returned HTTP ${response.status}.`
      : `Homepage did not return HTML (content type: ${contentType || 'unknown'}).`);
  }
  const text = stripHtml(await readLimitedText(response, MAX_HTML_BYTES));
  return { text, detail: text ? `Read ${text.length} characters of visible homepage text.` : 'The homepage had no readable text.' };
}

function parseModelOutput(content) {
  if (typeof content !== 'string') throw new Error('Model response did not contain text.');
  const trimmed = content.trim();
  const jsonText = trimmed.startsWith('```')
    ? trimmed.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '')
    : trimmed;
  const result = JSON.parse(jsonText);
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      Object.keys(result).sort().join(',') !== 'flags,score,summary' ||
      !Number.isInteger(result.score) || result.score < 0 || result.score > 100 ||
      !Array.isArray(result.flags) || result.flags.length > 20 ||
      !result.flags.every((flag) => typeof flag === 'string' && flag.trim() && flag.length <= 500) ||
      typeof result.summary !== 'string' || !result.summary.trim() || result.summary.length > 2000) {
    throw new Error('Model response did not match the score, flags, and summary schema.');
  }
  return {
    score: result.score,
    flags: result.flags.map((flag) => flag.trim()),
    summary: result.summary.trim(),
  };
}

async function analyzeWithModel(url, findings, homepageText, signal) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) throw new Error('GITHUB_TOKEN is not available.');
  const { response } = await fetchPublic('https://models.github.ai/inference/chat/completions', {
    method: 'POST',
    maxRedirects: 0,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      model: 'openai/gpt-4o-mini',
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: JSON.stringify({ website: url.toString(), findings, homepage_text: homepageText }) },
      ],
    }),
  }, signal);
  const data = await jsonResponse(response, 'GitHub Models');
  return parseModelOutput(data.choices?.[0]?.message?.content);
}

function weightedScore(age, history, reachability, model) {
  return Math.round(age * 0.3 + history * 0.2 + reachability * 0.2 + model * 0.3);
}

function interpretation(score) {
  if (score >= 80) return 'Strong indicators';
  if (score >= 60) return 'Generally positive, with areas to review';
  if (score >= 40) return 'Caution: mixed or limited signals';
  return 'High risk indicators';
}

function clean(value, maximum = 500) {
  return String(value).replace(/[\r\n]+/g, ' ').replace(/\|/g, '\\|')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;').trim().slice(0, maximum);
}

function formatComment(url, results, model, provisional) {
  const score = weightedScore(
    results.domainAge.score, results.wayback.score,
    results.reachability.score, model.score,
  );
  const rows = [
    ['Domain age', '30%', results.domainAge],
    ['Wayback history', '20%', results.wayback],
    ['HTTPS / reachability', '20%', results.reachability],
    ['Homepage / model analysis', '30%', { score: model.score, detail: model.detail }],
  ];
  const table = rows.map(([name, weight, result]) =>
    `| ${name} | ${weight} | ${result.score}/100 | ${clean(result.detail)} |`,
  ).join('\n');
  const flags = model.flags.length
    ? model.flags.map((flag) => `- ${clean(flag)}`).join('\n')
    : '- No specific red flags were identified.';
  return [
    '## Startup Trust Score',
    '',
    `**Score: ${score}/100 — ${interpretation(score)}${provisional ? ' (provisional)' : ''}**`,
    '',
    `Website: \`${clean(hostname(url), 253)}\``,
    '',
    '| Signal | Weight | Score | Finding |',
    '|---|---:|---:|---|',
    table,
    '',
    `**Analysis:** ${clean(model.summary, 1500)}`,
    '',
    '**Potential red flags:**',
    flags,
    '',
    '**Formula:** domain age × 30% + Wayback history × 20% + HTTPS/reachability × 20% + homepage/model analysis × 30%. Component scores are combined as a weighted average and rounded to the nearest whole number. A score of 80–100 means strong indicators; 60–79 generally positive; 40–59 caution; 0–39 high-risk indicators. This is an automated screening, not proof of legitimacy or fraud.',
    provisional
      ? '\n\n**Provisional:** at least one check or model analysis was unavailable. Unavailable components use a neutral score of 50/100 and are identified above.'
      : '',
  ].join('\n');
}

function resultOrNeutral(result, label) {
  if (result.status === 'fulfilled') return result.value;
  const message = result.reason instanceof Error ? result.reason.message : String(result.reason);
  return { score: 50, detail: `${label} unavailable: ${message}` };
}

async function postComment(body, signal) {
  const token = process.env.GITHUB_TOKEN;
  const repository = process.env.GITHUB_REPOSITORY || '';
  const issueNumber = Number(process.env.ISSUE_NUMBER);
  if (!token) throw new Error('GITHUB_TOKEN is not available; cannot post the issue comment.');
  if (!/^[^/]+\/[^/]+$/.test(repository) || !Number.isSafeInteger(issueNumber) || issueNumber < 1) {
    throw new Error('GITHUB_REPOSITORY or ISSUE_NUMBER is invalid.');
  }
  const apiBase = new URL(process.env.GITHUB_API_URL || 'https://api.github.com');
  if (apiBase.protocol !== 'https:') throw new Error('GITHUB_API_URL must use HTTPS.');
  const [owner, repo] = repository.split('/');
  const base = apiBase.href.endsWith('/') ? apiBase : new URL(`${apiBase.href}/`);
  const endpoint = new URL(
    `repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments`,
    base,
  );
  const { response } = await fetchPublic(endpoint, {
    method: 'POST',
    maxRedirects: 0,
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28',
    },
    body: JSON.stringify({ body }),
  }, signal);
  if (!response.ok) throw new Error(`GitHub issue comment failed with HTTP ${response.status}.`);
  await response.body?.cancel();
}

async function main() {
  let url;
  try {
    url = parseIssueUrl(process.env.ISSUE_BODY);
    await assertPublicUrl(url);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    const comment = `## Startup Trust Score\n\nUnable to check this website: ${clean(reason, 1000)}\n\nPlease open a new issue using the startup check form and enter one public HTTP or HTTPS URL.`;
    await withTimeout((signal) => postComment(comment, signal), 'Posting the validation error');
    throw error;
  }

  const [ageResult, waybackResult, reachabilityResult, homepageResult] = await Promise.allSettled([
    withTimeout((signal) => checkDomainAge(url, signal), 'Domain-age check'),
    withTimeout((signal) => checkWayback(url, signal), 'Wayback check'),
    withTimeout((signal) => checkReachability(url, signal), 'HTTPS and reachability check'),
    withTimeout((signal) => fetchHomepageText(url, signal), 'Homepage text check'),
  ]);
  const results = {
    domainAge: resultOrNeutral(ageResult, 'Domain-age check'),
    wayback: resultOrNeutral(waybackResult, 'Wayback check'),
    reachability: resultOrNeutral(reachabilityResult, 'HTTPS and reachability check'),
  };
  const homepage = homepageResult.status === 'fulfilled' ? homepageResult.value : {
    text: '',
    detail: `Homepage text unavailable: ${homepageResult.reason instanceof Error ? homepageResult.reason.message : String(homepageResult.reason)}`,
  };

  let model;
  try {
    model = await withTimeout((signal) => analyzeWithModel(url, {
      domain_age: results.domainAge.detail,
      wayback_history: results.wayback.detail,
      https_reachability: results.reachability.detail,
      homepage_text_status: homepage.detail,
    }, homepage.text, signal), 'GitHub Models analysis');
    model.detail = 'Model analysis completed.';
  } catch (error) {
    model = {
      score: 50,
      flags: [],
      summary: `Model analysis unavailable: ${error instanceof Error ? error.message : String(error)}`,
      detail: 'Model analysis unavailable; neutral score used.',
    };
  }
  const provisional = [ageResult, waybackResult, reachabilityResult, homepageResult]
    .some((result) => result.status === 'rejected') || model.detail !== 'Model analysis completed.';
  const comment = formatComment(url, results, model, provisional);
  await withTimeout((signal) => postComment(comment, signal), 'Posting the issue comment');
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`Startup trust check failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}

module.exports = {
  firstSnapshotDate,
  isUnsafeIp,
  parseIssueUrl,
  parseModelOutput,
  stripHtml,
  weightedScore,
};
