import { generateKeyPairSync } from "node:crypto";

export const serverId = `srv_${"a".repeat(26)}`;
export const orgId = `org_${"b".repeat(26)}`;
export const jobId = `job_${"c".repeat(26)}`;
export const cutoffId = `cut_${"d".repeat(26)}`;
export const nonce = Buffer.alloc(32, 7).toString("base64url");
export const rawPublicKey = Buffer.alloc(32, 9).toString("base64url");
export const at = "2030-01-01T00:00:00Z";
export const later = "2030-01-01T00:01:00Z";
export const person = { iss: "https://issuer.example.com", sub: "person-1" };
export const failure = { code: "example", action: "a person must act", message: "Example failure." };
export const running = { status: "running", job_id: jobId, vm: "vm-1", started_at: at };
export const page = { text: "hello", offset: 0, next_offset: 5, total_bytes: 5, dropped_before: 0 };
export const compact = "e30.e30.AA";
export const target = { kind: "name", name: "vm-1" };
export const cutoff = { type: "cutoff", cutoff_id: cutoffId, cursor: "cursor-1", person, at: 1000 };
export const hello = { typ: "tartlet-hello", server_id: serverId, nonce, iat: 1000, exp: 1060 };
export const poll = { typ: "tartlet-enroll-poll", device_code: "example-device-code", iat: 1000, exp: 1060 };
export const approval = { typ: "tartlet-enrollment", server_id: serverId, org_id: orgId, server_public_key: rawPublicKey, approver: person, nonce, iat: 1000, exp: 1600 };
export const proof = { typ: "tartlet-server-proof", server_id: serverId, origin: "https://server.example.com", nonce, iat: 1000, exp: 1060 };
export const claims = { typ: "tartlet-identity", iss: person.iss, aud: serverId, sub: person.sub, nonce, iat: 1000, nbf: 1000, exp: 1600, org: orgId, email: "person@example.com", email_verified: true };

export function field(value) {
  const bytes = typeof value === "string" ? Buffer.from(value) : value;
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}
export function sshKey(type, fields) {
  return `${type} ${Buffer.concat([field(type), ...fields.map(field)]).toString("base64")}`;
}
export function mpint(value) {
  const bytes = Buffer.from(value, "base64url");
  return bytes[0] >= 128 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes;
}
export const edPublic = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" });
export const publicKey = sshKey("ssh-ed25519", [Buffer.from(edPublic.x, "base64url")]);
export const connection = { host: "host.example.com", port: 22022, user: "guest", host_key_alias: "vm-1-instance", known_hosts_line: `vm-1-instance ${publicKey}` };
export const ssh = { ...connection, ssh_options: "example-options", command: "ssh example" };
export const vm = { name: "vm-1", label: "task-1", status: "running", image: "example-image", size: { cpu: 4, memory_mib: 8192, disk_gib: 80 }, network: "shared", persistent_home: false, home: { kind: "none" }, connect: [], ready: true, setup: { kind: "tartlet" }, ssh_keys_installed: true, reason: "Ready.", warnings: [], ssh, created_at: at };
