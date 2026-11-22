# @tartlet/protocol

`@tartlet/protocol` holds Zod schemas, TypeScript types, and small pure helpers for Tartlet, a self-hosted Mac VM console. The Tartlet server, its cloud sign-in service, and `@tartlet/cli` share this package.

## Where it runs

This package runs in Node.js 22+, Cloudflare Workers, and browsers. Node.js users need version 22.14.0 or later. The package depends only on `zod` and uses standard Web Crypto APIs with no Node-only code.

## Main exports

Every schema has a matching TypeScript type with the same base name, such as `VmSchema` and `Vm`.

- **IDs.** Branded schemas and type guards cover `PersonIdSchema`, `VmNameSchema`, `WorkerNameSchema`, `TaskLabelSchema`, `ServerIdSchema`, `OrganizationIdSchema`, `GrantTagSchema`, `JobIdSchema`, `ClientRequestIdSchema`, and `CutoffIdSchema`, with guards such as `isServerId` and `isVmName`.
- **Errors.** `ErrorActionSchema`, `ProtocolFailureSchema`, and `ErrorResponseSchema` define structured error responses.
- **Version check.** `PROTOCOL_VERSION`, `CliVersionSchema`, `VersionResponseSchema`, `isCompatible`, and `checkCompatibility` check protocol versions and tell callers which CLI version to run.
- **CLI and server schemas.** VM, SSH, and tunnel schemas include `VmSchema`, `VmTargetSchema`, `SshConnectionSchema`, `KnownHostsLineSchema`, `ListMyVmsResponseSchema`, `ServerProofRequestSchema`, `AuthorizeSshKeyRequestSchema`, `AuthorizeSshKeyResponseSchema`, `LinkRequestSchema`, `UnlinkRequestSchema`, and `TunnelOpenRequestSchema`. Command schemas include `RunCommandRequestSchema`, `GetCommandRequestSchema`, `CancelCommandRequestSchema`, `CommandStatusSchema`, and `OutputPageSchema`.
- **Server and cloud schemas.** Enrollment schemas include `EnrollmentStartRequestSchema`, `EnrollmentStartResponseSchema`, `EnrollmentPollRequestSchema`, and `JwsCompactSchema`. WebSocket message schemas include `ChallengeMessageSchema`, `HelloMessageSchema`, `WelcomeMessageSchema`, `KeyRefreshMessageSchema`, `CutoffMessageSchema`, `AckMessageSchema`, `CatchUpRequestMessageSchema`, `CatchUpMessageSchema`, `CloudToServerMessageSchema`, and `ServerToCloudMessageSchema`.
- **SSH public-key checks.** `parsePublicKey` and `PublicKeySchema` check one-line Ed25519, NIST ECDSA, and RSA 2048+ public keys with no options, and strip comments.
- **Canonical origins.** `normalizeOrigin` turns an HTTPS origin into its canonical form without a trailing slash or default port `443`. `CanonicalOriginSchema` accepts only that canonical form.
- **Signed artifacts.** `signJws` signs EdDSA payloads, and `readUnverifiedJwsHeader` reads `JwsHeaderSchema` so callers can pick a local key by `kid`. Per-artifact verifiers `verifyHello`, `verifyEnrollmentPoll`, `verifyEnrollmentApproval`, `verifyServerProof`, and `verifyIdentityToken` check the signature, the `CLOCK_SKEW_SECONDS` time window, the payload schema, and required context fields.
- **Cloud account IDs.** `CloudAccountIdSchema`, `CloudAccountId`, and `isCloudAccountId` check `acct_` IDs. Identity tokens, cloud access tokens, and enrollment approvals use these IDs for the subject. `PersonIdentitySchema` still accepts company OIDC subjects.
- **Enrollment polling and options.** `EnrollmentPollResponseSchema` checks enrollment poll responses. `parseEnrollmentPollResponse` returns a `ParsedEnrollmentPollResponse` with `kind` set to `"success"`, `"pending"`, or `"terminal"`. `EnrollmentStartRequestSchema` accepts optional `reenroll` and `https_trust` fields. `HttpsTrustSchema` accepts either `webpki` for public HTTPS roots or `local_ca` with `root_sha256`. `root_sha256` is the SHA-256 of the root certificate's DER-encoded SubjectPublicKeyInfo (SPKI) in lowercase hex. `EnrollmentAddressSchema` accepts an optional `port` field and rejects the default HTTPS port `443`.
- **Un-enroll.** `UnenrollChallengeRequestSchema` accepts only an empty body. The server ID goes in the URL path. `UnenrollChallengeResponseSchema` has `nonce` and `expires_in`. `UnenrollRequestSchema` has `proof`, and `UnenrollResponseSchema` has `unenrolled: true`. `UnenrollPayloadSchema` defines the proof payload. `verifyUnenroll` checks a signed proof from the server against the expected server ID and nonce.
- **Cloud server list.** `CloudAccessTokenClaimsSchema` defines cloud access token claims. `verifyCloudAccessToken` checks a token against the expected issuer and audience. `ServerListResponseSchema` accepts up to 500 servers with their addresses and online status.

## Signing rule

Issuers must sign with this package. `JwsHeaderSchema` allows only `alg: "EdDSA"` and an optional `kid`, so the strict JWS header rejects `typ: "JWT"` and extra fields such as `jku`, `jwk`, and `x5u`.

## Example

This example signs a synthetic server proof and checks it with `verifyServerProof`:

```ts
import {
  ServerIdSchema,
  normalizeOrigin,
  signJws,
  verifyServerProof,
} from "@tartlet/protocol";

const keys = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
const serverId = ServerIdSchema.parse("srv_aaaaaaaaaaaaaaaaaaaaaaaaaa");
const origin = normalizeOrigin("https://server.example.com/");
const nonce = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";
const now = Math.floor(Date.now() / 1000);

const jws = await signJws({
  payload: {
    typ: "tartlet-server-proof",
    server_id: serverId,
    origin,
    nonce,
    iat: now,
    exp: now + 60,
  },
  private_key: keys.privateKey,
  kid: "key-1",
});

const proof = await verifyServerProof({
  jws,
  public_key: keys.publicKey,
  expected: { server_id: serverId, origin, nonce },
  now,
});
```

## License

This package uses the Apache-2.0 license. See `LICENSE`.
