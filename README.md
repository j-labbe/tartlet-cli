# Tartlet CLI

This repository holds the public npm packages for Tartlet, a self-hosted Mac VM console.

## Packages

- `@tartlet/protocol` lives in `packages/protocol`. It holds Zod schemas, TypeScript types, and small pure helpers that the Tartlet server, its cloud sign-in service, and the CLI share.
- `@tartlet/cli` is coming soon. It will be a command-line tool that you run with `npx @tartlet/cli@<version>`. This package is not built yet.

## Build and test

Install Node.js 22.14.0 or later, then run these commands from the repository root:

```sh
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

## Releases

CI stages each release with npm trusted publishing and provenance. A maintainer approves each release before npm publishes it.

## Security

Report security issues privately through GitHub's private vulnerability reporting on this repository. Do not open a public issue for a vulnerability.

## License

This repository uses the Apache-2.0 license. See `LICENSE`.
