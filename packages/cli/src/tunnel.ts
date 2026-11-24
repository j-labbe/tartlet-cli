import { WebSocket, createWebSocketStream } from "ws";
import { tlsOptions } from "./http.js";
import { networkError, responseError } from "./errors.js";
import type { Access } from "./access.js";

export async function openTunnel(access: Access) {
  const url = new URL(`/api/agent/tunnel/name/${encodeURIComponent(access.vm)}`, access.profile.origin);
  url.protocol = "wss:";
  const socket = new WebSocket(url, { ...tlsOptions(access.profile.trust), headers: { Authorization: `Bearer ${access.profile.tokens.access_token}` },
    followRedirects: false, perMessageDeflate: false, maxPayload: 256 * 1024, handshakeTimeout: 30000 });
  return new Promise<ReturnType<typeof createWebSocketStream>>((resolve, reject) => {
    socket.once("error", (error) => reject(networkError(error)));
    socket.once("unexpected-response", (_req, res) => {
      const chunks: Buffer[] = []; let size = 0;
      res.on("data", (chunk: Buffer) => { size += chunk.length; if (size > 32768) res.destroy(); else chunks.push(chunk); });
      res.once("error", reject);
      res.once("end", () => {
        let body: unknown;
        try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { body = {}; }
        reject(responseError(res.statusCode ?? 0, body)); socket.terminate();
      });
      res.once("close", () => { reject(new Error("The server refused the connection to the VM.")); socket.terminate(); });
    });
    socket.once("open", () => {
      const stream = createWebSocketStream(socket, { highWaterMark: 65536 });
      stream.on("error", () => socket.terminate());
      stream.once("close", () => socket.terminate());
      resolve(stream);
    });
  });
}
