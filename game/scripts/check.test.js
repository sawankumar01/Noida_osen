'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  firstSnapshotDate,
  isUnsafeIp,
  parseIssueUrl,
  parseModelOutput,
  stripHtml,
  weightedScore,
} = require('./check');

test('extracts the required URL field from an issue form body', () => {
  assert.equal(parseIssueUrl('### Startup website URL\n\nhttps://example.com/path\n').href,
    'https://example.com/path');
});

test('rejects unsupported schemes and URL credentials', () => {
  assert.throws(() => parseIssueUrl('### Startup website URL\n\nfile:///etc/passwd'));
  assert.throws(() => parseIssueUrl('### Startup website URL\n\nhttps://user:pass@example.com'));
});

test('blocks private and special-purpose IP ranges', () => {
  for (const address of ['127.0.0.1', '10.1.2.3', '169.254.1.2', '::1', 'fc00::1', '::ffff:192.168.1.2']) {
    assert.equal(isUnsafeIp(address), true, `${address} should be blocked`);
  }
  for (const address of ['8.8.8.8', '2606:4700:4700::1111']) {
    assert.equal(isUnsafeIp(address), false, `${address} should be allowed`);
  }
});

test('validates model output and accepts an outer JSON code fence', () => {
  assert.deepEqual(
    parseModelOutput('```json\n{"score":72,"flags":["No team listed"],"summary":"Limited information."}\n```'),
    { score: 72, flags: ['No team listed'], summary: 'Limited information.' },
  );
  assert.throws(() => parseModelOutput('{"score":101,"flags":[],"summary":"bad"}'));
  assert.throws(() => parseModelOutput('{"score":72,"flags":[],"summary":"ok","extra":true}'));
});

test('calculates weighted score and extracts visible HTML text', () => {
  assert.equal(weightedScore(100, 80, 60, 50), 74);
  assert.equal(stripHtml('<h1>Good&nbsp;startup</h1><script>hidden()</script><p>Builds &amp; ships</p>'),
    'Good startup Builds & ships');
});

test('reads the first Wayback CDX timestamp', () => {
  assert.equal(firstSnapshotDate([['timestamp'], ['20180102030405']]).toISOString().slice(0, 10),
    '2018-01-02');
});
