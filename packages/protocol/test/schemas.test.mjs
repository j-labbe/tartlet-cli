import assert from "node:assert/strict";
import test from "node:test";
import * as p from "@tartlet/protocol";
import * as f from "./fixtures.mjs";

const fixtures = {
  PersonIdSchema: ["person_1", "person..1"],
  VmNameSchema: ["vm-1", "VM-1"],
  TaskLabelSchema: ["task-1", "a".repeat(17)],
  ServerIdSchema: [f.serverId, `srv_${"0".repeat(26)}`],
  OrganizationIdSchema: [f.orgId, f.serverId],
  GrantTagSchema: [`grt_${"e".repeat(26)}`, "grt_short"],
  JobIdSchema: [f.jobId, f.serverId],
  ClientRequestIdSchema: ["request-1", "short"],
  CutoffIdSchema: [f.cutoffId, "cut_short"],
  ErrorActionSchema: ["change your input", "retry"],
  ProtocolFailureSchema: [f.failure, { ...f.failure, action: "retry" }],
  ErrorResponseSchema: [{ error: f.failure }, f.failure],
  CanonicalOriginSchema: ["https://server.example.com", "https://SERVER.example.com/"],
  HttpsUrlSchema: ["https://issuer.example.com", "https://@issuer.example.com"],
  DeviceCodeSchema: ["example-device-code", "a".repeat(129)],
  SshUserSchema: ["guest", "-guest"],
  HostKeyAliasSchema: ["vm-1-instance", "#alias"],
  NonceSchema: [f.nonce, "AA"],
  ServerPublicKeySchema: [f.rawPublicKey, "AA"],
  UnixTimeSchema: [1000, -1],
  TimestampSchema: [f.at, "yesterday"],
  CursorSchema: ["cursor-1", ""],
  PersonIdentitySchema: [f.person, { ...f.person, email: "extra@example.com" }],
  HostSchema: ["host.example.com", "host.example.com/path"],
  PortSchema: [22, 65536],
  CliVersionSchema: ["1.2.3-beta.1", "latest; echo unsafe"],
  VersionResponseSchema: [{ protocol_version: 1, cli_version: "1.2.3" }, { protocol_version: 1, cli_version: "latest" }],
  PublicKeySchema: [f.publicKey, `restrict ${f.publicKey}`],
  OutputPageSchema: [f.page, { ...f.page, next_offset: 6 }],
  CommandStatusSchema: [f.running, { ...f.running, exit_code: 0 }],
  RunCommandRequestSchema: [{ client_request_id: "request-1", vm: "vm-1", command: "printf hello" }, { client_request_id: "request-1", vm: "vm-1", command: "echo", timeout_seconds: 7201 }],
  GetCommandRequestSchema: [{ job_id: f.jobId, vm: "vm-1" }, { job_id: f.jobId, vm: "vm-1", max_bytes: 65537 }],
  CancelCommandRequestSchema: [{ job_id: f.jobId, vm: "vm-1" }, { job_id: f.jobId }],
  RunCommandResponseSchema: [f.running, { ...f.running, status: "queued" }],
  GetCommandResponseSchema: [{ job: f.running, stdout: f.page, stderr: f.page }, { job: f.running, stdout: f.page }],
  CancelCommandResponseSchema: [{ ...f.running, status: "canceled", finished_at: f.later }, { ...f.running, status: "canceled" }],
  HelloPayloadSchema: [f.hello, { ...f.hello, exp: 1061 }],
  EnrollmentPollPayloadSchema: [f.poll, { ...f.poll, exp: 1061 }],
  EnrollmentApprovalPayloadSchema: [f.approval, { ...f.approval, exp: 1601 }],
  ServerProofPayloadSchema: [f.proof, { ...f.proof, origin: "http://server.example.com" }],
  IdentityTokenClaimsSchema: [f.claims, { ...f.claims, name: "Extra personal data" }],
  SignedPayloadSchema: [f.proof, { ...f.proof, typ: "unknown" }],
  JwsCompactSchema: [f.compact, "e30.e30.AA.extra"],
  EnrollmentAddressSchema: [{ kind: "lan", host: "server.example.com" }, { kind: "internet", host: "example.com" }],
  EnrollmentStartRequestSchema: [{ server_public_key: f.rawPublicKey, server_name: "Server 1", addresses: [{ kind: "tailnet", host: "server.example.com" }], nonce: f.nonce }, { server_public_key: f.rawPublicKey, server_name: "Server 1", addresses: [], nonce: f.nonce }],
  EnrollmentStartResponseSchema: [{ device_code: "example-device-code", user_code: "ABCD-2345", verification_uri: "https://cloud.example.com/verify", expires_in: 600, interval: 5 }, { device_code: "example-device-code", user_code: "0000-1111", verification_uri: "https://cloud.example.com/verify", expires_in: 600, interval: 5 }],
  EnrollmentPollRequestSchema: [{ device_code: "example-device-code", proof: f.compact }, { device_code: "example-device-code", proof: "bad" }],
  ChallengeMessageSchema: [{ type: "challenge", nonce: f.nonce, issued_at: 1000 }, { type: "challenge", nonce: "bad", issued_at: 1000 }],
  HelloMessageSchema: [{ type: "hello", server_id: f.serverId, protocol_version: 1, proof: f.compact }, { type: "hello", server_id: f.serverId, protocol_version: 1 }],
  WelcomeMessageSchema: [{ type: "welcome", head_cursor: "cursor-0" }, { type: "welcome", head_cursor: null }],
  KeyRefreshMessageSchema: [{ type: "key_refresh" }, { type: "key_refresh", jwks_uri: "https://attacker.example.com" }],
  CutoffMessageSchema: [f.cutoff, { ...f.cutoff, cursor: "" }],
  AckMessageSchema: [{ type: "ack", cutoff_ids: [f.cutoffId] }, { type: "ack", cutoff_ids: [] }],
  CatchUpRequestMessageSchema: [{ type: "catch_up_request", after_cursor: null }, { type: "catch_up_request", after_cursor: 1 }],
  CatchUpMessageSchema: [{ type: "catch_up", cutoffs: [f.cutoff], next_cursor: "cursor-1", complete: true }, { type: "catch_up", cutoffs: [], next_cursor: null }],
  CloudMessageSchema: [f.cutoff, { type: "command", command: "unsafe" }],
  CloudToServerMessageSchema: [f.cutoff, { type: "ack", cutoff_ids: [f.cutoffId] }],
  ServerToCloudMessageSchema: [{ type: "ack", cutoff_ids: [f.cutoffId] }, f.cutoff],
  VmTargetSchema: [f.target, { kind: "label", name: "vm-1" }],
  SetupSchema: [{ kind: "tartlet" }, { kind: "none" }],
  KnownHostsLineSchema: [f.connection.known_hosts_line, `@cert-authority ${f.publicKey}`],
  SshConnectionSchema: [f.ssh, { ...f.ssh, host_key_alias: "wrong" }],
  VmHomeSchema: [{ kind: "host", host: "host.example.com", path: "/synthetic/home", mount_name: "home" }, { kind: "nas" }],
  VmConnectionSchema: [{ name: "SSH", guest_port: 22, connection: { kind: "ssh", command: "ssh example" } }, { name: "SSH", guest_port: 22, connection: { kind: "ssh" } }],
  VmSchema: [f.vm, { ...f.vm, status: "pending" }],
  ListMyVmsRequestSchema: [{}, { owner: "another-person" }],
  ListMyVmsResponseSchema: [{ vms: [f.vm] }, { vms: [null] }],
  ServerProofRequestSchema: [{ nonce: f.nonce }, { nonce: "short" }],
  ServerProofResponseSchema: [f.compact, "bad"],
  AuthorizeSshKeyRequestSchema: [{ vm: "vm-1", public_key: f.publicKey }, { vm: "vm-1", public_key: f.publicKey, lifetime_minutes: 61 }],
  AuthorizeSshKeyResponseSchema: [{ ...f.connection, expires_at: f.later }, { ...f.connection, expires_at: f.later, port: 0 }],
  LinkRequestSchema: [{ vm: f.target, public_key: f.publicKey }, { vm: f.target, public_key: `restrict ${f.publicKey}` }],
  LinkResponseSchema: [{ vm: "vm-1", public_key: f.publicKey, linked: true }, { vm: "vm-1", public_key: f.publicKey, linked: false }],
  UnlinkRequestSchema: [{ vm: { kind: "label", label: "task-1" }, public_key: f.publicKey }, { vm: f.target }],
  UnlinkResponseSchema: [{ vm: "vm-1", public_key: f.publicKey, linked: false }, { vm: "vm-1", public_key: f.publicKey, linked: true }],
  TunnelOpenRequestSchema: [{ vm: f.target }, { vm: f.target, token: "forbidden" }],
  JwsHeaderSchema: [{ alg: "EdDSA", kid: "key-1" }, { alg: "HS256" }],
};

test("every exported schema has valid and invalid contract cases", () => {
  const names = Object.keys(p).filter((name) => name.endsWith("Schema")).sort();
  assert.deepEqual(Object.keys(fixtures).sort(), names);
});
for (const [name, [valid, invalid]] of Object.entries(fixtures)) {
  test(name, () => {
    const result = p[name].safeParse(valid);
    assert.equal(result.success, true, result.error?.message);
    assert.equal(p[name].safeParse(invalid).success, false, `${name} must reject its invalid case`);
    assert.equal(p[name].safeParse(null).success, false, `${name} must reject null`);
  });
}

test("ID guards preserve existing person IDs and all exact boundaries", () => {
  for (const value of ["dev", "Person_1", "123e4567-e89b-12d3-a456-426614174000", "a".repeat(64)]) assert.equal(p.isPersonId(value), true);
  for (const value of ["", ".person", "a..b", "a".repeat(65), null]) assert.equal(p.isPersonId(value), false);
  const cases = [
    [p.isVmName, "a".repeat(63), "a".repeat(64)],
    [p.isTaskLabel, "a".repeat(16), "a".repeat(17)],
    [p.isServerId, f.serverId, f.serverId.toUpperCase()],
    [p.isOrganizationId, f.orgId, f.serverId],
    [p.isGrantTag, `grt_${"2".repeat(26)}`, `grt_${"1".repeat(26)}`],
    [p.isJobId, f.jobId, f.jobId.slice(0, -1)],
    [p.isClientRequestId, "a".repeat(64), "a".repeat(65)],
    [p.isCutoffId, f.cutoffId, `${f.cutoffId}a`],
  ];
  for (const [guard, valid, invalid] of cases) { assert.equal(guard(valid), true); assert.equal(guard(invalid), false); }
});

test("request defaults and limits", () => {
  assert.equal(p.AuthorizeSshKeyRequestSchema.parse({ vm: "vm-1", public_key: `${f.publicKey} person@example.com` }).lifetime_minutes, 10);
  assert.equal(p.RunCommandRequestSchema.parse({ client_request_id: "request-1", vm: "vm-1", command: "echo" }).timeout_seconds, 1800);
  assert.deepEqual(p.GetCommandRequestSchema.parse({ job_id: f.jobId, vm: "vm-1" }), { job_id: f.jobId, vm: "vm-1", stdout_offset: 0, stderr_offset: 0, max_bytes: 16384 });
  assert.equal(p.GetCommandRequestSchema.safeParse({ job_id: f.jobId, vm: "vm-1", max_bytes: 65536 }).success, true);
  assert.equal(p.AckMessageSchema.safeParse({ type: "ack", cutoff_ids: Array(100).fill(f.cutoffId) }).success, true);
  assert.equal(p.AckMessageSchema.safeParse({ type: "ack", cutoff_ids: Array(101).fill(f.cutoffId) }).success, false);
});

test("all command states enforce variant fields and completion times", () => {
  for (const status of ["exited", "canceled", "timed_out", "lost", "failed_to_start"]) {
    const extra = status === "exited" ? { exit_code: 255 } : status === "failed_to_start" ? { error: f.failure } : {};
    const value = { ...f.running, status, finished_at: f.later, ...extra };
    assert.equal(p.CommandStatusSchema.safeParse(value).success, true);
    assert.equal(p.CommandStatusSchema.safeParse({ ...value, finished_at: "2029-01-01T00:00:00Z" }).success, false);
  }
  assert.equal(p.CommandStatusSchema.safeParse({ ...f.running, status: "exited", finished_at: f.later, exit_code: 256 }).success, false);
  assert.equal(p.CommandStatusSchema.safeParse({ ...f.running, finished_at: f.later }).success, false);
});

test("output uses raw-byte offsets, replacement text and a bounded retained suffix", () => {
  assert.equal(p.OutputPageSchema.safeParse({ ...f.page, text: "é", next_offset: 2, total_bytes: 2 }).success, true);
  assert.equal(p.OutputPageSchema.safeParse({ ...f.page, text: "\uFFFD", next_offset: 1, total_bytes: 1 }).success, true);
  assert.equal(p.OutputPageSchema.safeParse({ ...f.page, text: "😀", next_offset: 4, total_bytes: 4 }).success, true);
  assert.equal(p.OutputPageSchema.safeParse({ ...f.page, text: "\uD800" }).success, false);
  assert.equal(p.OutputPageSchema.safeParse({ ...f.page, next_offset: 4 }).success, false);
  const offset = 9000;
  const retained = { text: "ok", offset, next_offset: offset + 2, total_bytes: offset + 4 * 1024 * 1024, dropped_before: offset };
  assert.equal(p.OutputPageSchema.safeParse(retained).success, true);
  assert.equal(p.OutputPageSchema.safeParse({ ...retained, offset: offset - 1 }).success, false);
  assert.equal(p.OutputPageSchema.safeParse({ ...retained, total_bytes: retained.total_bytes + 1 }).success, false);
  assert.equal(p.GetCommandRequestSchema.safeParse({ job_id: f.jobId, vm: "vm-1", stdout_offset: -1 }).success, false);
});

test("cloud messages reject every undeclared message type and trust field", () => {
  for (const type of ["online", "ping", "device_approval", "run_command", "ssh", "unknown"]) assert.equal(p.CloudMessageSchema.safeParse({ type }).success, false);
  for (const field of ["url", "key", "jwk", "issuer", "trust_root"]) assert.equal(p.KeyRefreshMessageSchema.safeParse({ type: "key_refresh", [field]: "forbidden" }).success, false);
  for (const [name, [valid]] of Object.entries(fixtures).filter(([name]) => name.endsWith("MessageSchema"))) assert.equal(p[name].safeParse({ ...valid, unexpected: true }).success, false);
});

test("version compatibility is exact and produces a safely pinned invocation", () => {
  assert.equal(p.PROTOCOL_VERSION, 1);
  assert.equal(p.isCompatible(1), true);
  assert.equal(p.isCompatible(2), false);
  assert.equal(p.checkCompatibility({ protocol_version: 1, cli_version: "0.1.0" }), undefined);
  assert.deepEqual(p.checkCompatibility({ protocol_version: 2, cli_version: "1.2.3" }), { error: { code: "incompatible_protocol", action: "change your input", message: "Run npx @tartlet/cli@1.2.3." } });
});

test("VM list fields retain MCP values with snake_case wire names", () => {
  const homes = [
    { kind: "none" },
    { kind: "host", host: "host.example.com", path: "/synthetic/home", mount_name: "home" },
    { kind: "nas", path: "/synthetic/home", mount_name: "home" },
    { kind: "volume", health: "healthy", mode: "durable", copy_count: 1, safety: "Example safety", copies: [{ host: "host.example.com", role: "primary" }], progress: { phase: "filling", completed_bytes: "100", total_bytes: "200", percent: 50, message: "Example progress" } },
    { kind: "volume", health: "degraded", mode: "memory", copy_count: 0, safety: "Example safety", copies: [], progress: { phase: "recovering", message: "Example recovery" } },
  ];
  for (const home of homes) assert.equal(p.VmSchema.safeParse({ ...f.vm, home }).success, true);
  assert.equal(p.VmHomeSchema.safeParse({ ...homes[1], mountName: "camelCase" }).success, false);
  const connections = [{ kind: "pending" }, { kind: "unsupported" }, { kind: "ssh", command: "ssh example" }, { kind: "screen-sharing", url: "vnc://guest@host.example.com:5900" }, { kind: "port", address: "host.example.com:8080" }];
  for (const connection of connections) assert.equal(p.VmConnectionSchema.safeParse({ name: "example", guest_port: 22, connection }).success, true);
  assert.equal(p.TunnelOpenRequestSchema.safeParse({ vm: f.target, authorization: "forbidden" }).success, false);
});
