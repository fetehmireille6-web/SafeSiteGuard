const assert = require('node:assert/strict');
const { shouldBlockWarning } = require('../extension/decision.js');

assert.equal(shouldBlockWarning('dangerous', true), true);
assert.equal(shouldBlockWarning('caution', true), true);
assert.equal(shouldBlockWarning('caution', false), false);
assert.equal(shouldBlockWarning('safe', false), false);
assert.equal(shouldBlockWarning('safe', true, 'http://demo.testfire.net/'), true);
assert.equal(shouldBlockWarning('safe', true, 'https://example.com/'), false);
assert.equal(shouldBlockWarning('safe', true, 'https://loginhelpdesk.com/'), false);
assert.equal(shouldBlockWarning('safe', true, 'https://10.0.0.5/'), false);
assert.equal(shouldBlockWarning('safe', true, 'https://8.8.8.8/'), true);
assert.equal(shouldBlockWarning('safe', true, 'https://secure-login-update-account.com/'), true);
assert.equal(shouldBlockWarning('safe', true, 'https://example.com/', false, 'revoked'), true);
assert.equal(shouldBlockWarning('safe', true, 'https://example.com/', false, 'expired'), true);
assert.equal(shouldBlockWarning('dangerous', true, 'https://example.com/', true), false);
assert.equal(shouldBlockWarning('safe', true, 'http://example.com/', true), false);
assert.equal(shouldBlockWarning('safe', true, 'https://example.com/', false, 'valid'), false);

console.log('decision tests passed');
