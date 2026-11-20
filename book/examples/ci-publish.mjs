import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  policy, external, delegated, isSelf, canonicalJson, docHash,
} from '../../packages/perch-js/dist/index.js';

const fixture = JSON.parse(readFileSync(
  new URL('../../testdata/ci-publish-delegated.json', import.meta.url), 'utf8',
));
const [admin, ci] = fixture.signers;
const release = fixture.rules[1];

const doc = policy()
  .network(fixture.network)
  .signer('admin', external(admin.verifier, admin.key))
  .signer('ci', delegated(ci.address))
  .rule('admin', r => r.selfAdmin().signedBy('admin'))
  .rule('ci-publish', r => r
    .callContract(release.scope.address)
    .signedBy('ci')
    .func('publish', 'publish_hash')
    .arg(1, isSelf())
    .notAfter(release['not-after-ledger']))
  .build();

assert.deepEqual(doc, fixture);
console.log(canonicalJson(doc));
console.log(docHash(doc));
