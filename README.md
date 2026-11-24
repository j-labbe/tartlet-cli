# Tartlet CLI

Public npm packages for Tartlet, a self-hosted Mac VM console.

- [`@tartlet/cli`](packages/cli/README.md) provides the `tartlet` command for sign-in, SSH, file copy, and native SSH proxy connections.
- [`@tartlet/protocol`](packages/protocol/README.md) provides shared schemas, types, and pure helpers.

## Build and test

Install Node.js 22.14 or later, then run these commands from the repository root:

```sh
npm ci
npm run typecheck
npm run lint
npm test
npm run build
npm run pack:check
npm run pack:smoke
```

## Releases

The release workflow stages both npm archives. Publishing uses npm trusted
publishing with provenance and waits for approval in the `npm-release` environment.
Configure that environment with the owner's required review, and configure each
npm package's trusted publisher before enabling publication. The owner uses
2FA for release approval. The workflow creates no tags.

## Security

Report security issues through this repository's private vulnerability reporting.
Do not open a public issue for a vulnerability.

## License

Apache-2.0. See `LICENSE`.
