'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { verifySignature } = require('../dist/nodes/Secuveri/SecuveriTrigger.node.js');
const { Secuveri } = require('../dist/nodes/Secuveri/Secuveri.node.js');

test('deliveries are accepted only with a fresh, matching signature', () => {
  const body = '{"id":"evt_1","type":"verification.completed"}';
  const now = 1_800_000_000_000;
  const t = now / 1000;
  const sign = (secret, at = t) => `t=${at},v1=${crypto.createHmac('sha256', secret).update(`${at}.${body}`).digest('hex')}`;
  assert.ok(verifySignature(body, sign('whsec_a'), 'whsec_a', now));
  assert.ok(!verifySignature(body, sign('whsec_b'), 'whsec_a', now));
  assert.ok(!verifySignature(body, sign('whsec_a', t - 600), 'whsec_a', now));
  assert.ok(!verifySignature(body, undefined, 'whsec_a', now));
  assert.ok(!verifySignature(body, sign('whsec_a'), undefined, now));
});

test('the action node offers verification, AML and list operations', () => {
  const resources = new Secuveri().description.properties.find((p) => p.name === 'resource').options.map((o) => o.value);
  assert.deepStrictEqual(resources, ['verification', 'amlScreening', 'listEntry']);
});
