# n8n-nodes-secuveri

[secuveri](https://secuveri.com) for [n8n](https://n8n.io): identity verification, AML screening and block lists.

- **secuveri** node: create a verification link (optionally sent by email or SMS), get one or many finished verifications, screen a person against sanctions lists and PEPs, add to a block or allow list.
- **secuveri Trigger**: starts a workflow when a verification finishes (any outcome, approved, or declined), needs review or expires. It subscribes a webhook when the workflow is activated and checks every delivery's signature.

## Credentials

An organization API key from **Settings > API keys** in the [secuveri dashboard](https://app.secuveri.com), with the scopes your workflows use: *Read results*, *Create sessions*, *Manage webhooks*, and *AML screening* or *Change lists*. A `sk_test_` key works in the sandbox.

## Install

In n8n: **Settings > Community nodes > Install**, package `n8n-nodes-secuveri`.

## Develop

```sh
npm install
npm run build && npm run lint && npm test
```

Releases are published from GitHub Actions with npm provenance, which n8n requires for verified nodes: bump `version` in `package.json`, then push a tag `v<version>` (for example `v0.1.0`). Then submit the package in the n8n Creator Portal for verification.

MIT licence.
