# Tartlet CLI

Public npm packages for Tartlet, a self-hosted Mac VM console.

- [`@tartlet/cli`](packages/cli/README.md) is the `tartlet` command. Use it to sign in,
  open SSH sessions, copy files and connect OpenSSH or VS Code to your VMs.
- [`@tartlet/protocol`](packages/protocol/README.md) holds the schemas, types and small
  helpers that Tartlet and the CLI share.

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

The release workflow builds and tests both npm packages. When you start it with
`publish` on, it waits for approval in the `npm-release` environment and then
publishes with npm trusted publishing and provenance. Before you turn on publishing,
set that environment to require the owner's review, and set a trusted publisher for
each npm package. The owner approves releases with 2FA. The workflow does not create
tags.

## Security

Report security issues through this repository's private vulnerability reporting.
Do not open a public issue for a vulnerability.

## License

Apache-2.0. See `LICENSE`.
