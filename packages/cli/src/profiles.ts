import { ServerListResponseSchema, normalizeOrigin, type ServerListResponse } from "@tartlet/protocol";
import { json, localTrust, type Endpoint } from "./http.js";
import { discover, signIn, verifyCloudToken, type SignInIO } from "./oauth.js";
import { changeState, readState, readUtf8, selectProfile, TokensSchema, type Profile, type Trust } from "./storage.js";
import { form } from "./http.js";

export interface LoginIO extends SignInIO { choose: (message: string, options: string[]) => Promise<number> }
export interface LoginOptions { directory: string; server?: string; profile?: string; ca?: string; device: boolean; io: LoginIO; cloud?: Endpoint }
function originOf(address: ServerListResponse["servers"][number]["addresses"][number]) {
  const host = address.host.includes(":") ? `[${address.host}]` : address.host;
  return normalizeOrigin(`https://${host}${address.port === undefined ? "" : `:${address.port}`}`);
}
async function fromCloud(options: LoginOptions) {
  const cloud = options.cloud ?? { origin: "https://app.tartlet.io", trust: { kind: "webpki" } }, metadata = await discover(cloud, true);
  const { tokens } = await signIn({ endpoint: cloud, metadata, device: options.device, cloud: true, io: options.io });
  await verifyCloudToken(cloud, metadata, tokens.access_token);
  const { servers } = await json({ endpoint: cloud, url: `${cloud.origin}/v1/servers`, headers: { Authorization: `Bearer ${tokens.access_token}` } }, ServerListResponseSchema);
  if (!servers.length) throw new Error("No servers are available for this account. Ask a server administrator for access.");
  const server = servers[await options.io.choose("Choose a server", servers.map((entry) => `${entry.name} (${entry.online ? "online" : "offline"})`))];
  if (!server) throw new Error("Choose one of the listed servers.");
  const state = await readState(options.directory), named = state.profiles.find((entry) => entry.name === options.profile);
  if (named?.server_id && named.server_id !== server.server_id) throw new Error("The selected profile belongs to a different server. Choose its server from the list, or use another --profile name.");
  const saved = named ?? state.profiles.find((entry) => entry.server_id === server.server_id);
  if (saved) return { origin: saved.origin, server_id: server.server_id, saved };
  const address = server.addresses[await options.io.choose("Choose a server address", server.addresses.map((entry) => `${originOf(entry)} (${entry.kind})`))];
  if (!address) throw new Error("Choose one of the listed addresses.");
  const origin = originOf(address);
  return { origin, server_id: server.server_id, saved: state.profiles.find((entry) => entry.origin === origin) };
}
async function target(options: LoginOptions) {
  if (!options.server) return fromCloud(options);
  const origin = normalizeOrigin(options.server), state = await readState(options.directory);
  const saved = state.profiles.find((entry) => options.profile ? entry.name === options.profile : entry.origin === origin);
  if (saved && saved.origin !== origin) throw new Error("This profile already has a different saved origin. Use a new --profile name.");
  return { origin, server_id: saved?.server_id, saved };
}
async function loginTrust(options: LoginOptions, saved: Profile | undefined): Promise<Trust> {
  if (!options.ca) return saved?.trust ?? { kind: "webpki" };
  const trust = localTrust(await readUtf8(options.ca));
  if (saved && JSON.stringify(saved.trust) !== JSON.stringify(trust)) throw new Error("This profile already has different HTTPS trust. Use a new --profile name after verifying the root CA.");
  return trust;
}
export async function login(options: LoginOptions): Promise<Profile> {
  const selected = await target(options), trust = await loginTrust(options, selected.saved);
  const endpoint = { origin: selected.origin, trust }, metadata = await discover(endpoint);
  const result = await signIn({ endpoint, metadata, device: options.device, cloud: false, io: options.io });
  const name = options.profile ?? selected.saved?.name ?? selected.server_id ?? new URL(selected.origin).host.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64);
  const profile: Profile = { name, ...endpoint, ...result, expires_at: Date.now() + result.tokens.expires_in * 1000, ...(selected.server_id ? { server_id: selected.server_id } : {}) };
  await changeState(options.directory, async (state) => {
    const previous = state.profiles.find((entry) => entry.name === name);
    if (previous && (previous.origin !== profile.origin || JSON.stringify(previous.trust) !== JSON.stringify(profile.trust))) throw new Error("The saved profile changed while signing in. Try again with a new --profile name.");
    state.profiles = state.profiles.filter((entry) => entry.name !== name); state.profiles.push(profile); state.active = name;
  });
  options.io.say(`Signed in to ${profile.origin}. Profile: ${profile.name}.`);
  return profile;
}
export async function connectedProfile(directory: string, name?: string): Promise<Profile> {
  return changeState(directory, async (state) => {
    const profile = selectProfile(state, name);
    if (profile.expires_at > Date.now() + 30000) return profile;
    if (!profile.tokens.refresh_token) throw new Error("Your sign-in has expired. Run tartlet login again.");
    const metadata = await discover(profile);
    const tokens = await json(form(profile, metadata.token_endpoint, { grant_type: "refresh_token", client_id: profile.client_id, refresh_token: profile.tokens.refresh_token, resource: `${profile.origin}/mcp` }), TokensSchema);
    profile.tokens = { ...tokens, refresh_token: tokens.refresh_token ?? profile.tokens.refresh_token };
    profile.expires_at = Date.now() + tokens.expires_in * 1000;
    return profile;
  });
}
