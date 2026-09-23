import http from "node:http";
import https from "node:https";
import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { WebSocket, WebSocketServer } from "ws";

const ROOT = resolve(fileURLToPath(new URL(".", import.meta.url)));
const PUBLIC_ROOT = resolve(ROOT, "public");
const IS_RAILWAY = Boolean(
  process.env.RAILWAY_ENVIRONMENT
  || process.env.RAILWAY_ENVIRONMENT_NAME
  || process.env.RAILWAY_PUBLIC_DOMAIN,
);
const HOST = process.env.HOST ?? (IS_RAILWAY ? "0.0.0.0" : "127.0.0.1");
const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65_535) {
  throw new Error("Invalid PORT");
}
const POW_DIFFICULTY = integerSetting("POW_DIFFICULTY", 16, 12, 20);
const GRACE_MS = integerSetting("SESSION_GRACE_MS", 8_000, 1_000, 30_000);
const MAX_SESSIONS = integerSetting("MAX_SESSIONS", 10_000, 1, 100_000);
const MAX_CHATS = integerSetting("MAX_CHATS", 10_000, 1, 100_000);
const MAX_PENDING_PER_SESSION = 5;
const MAX_POW_CHALLENGES = 10_000;
const MAX_MESSAGE_BYTES = 2_048;
const MAX_WS_PAYLOAD = 16 * 1024;
const SESSION_GRACE_SECONDS = 120;
const MAX_BUFFERED_BYTES = 256 * 1024;

const sessions = new Map();
const chats = new Map();
const dialogRequests = new Map();
const powChallenges = new Map();
const rateBuckets = new Map();

const contentSecurityPolicyBase = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'none'",
  "font-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  "object-src 'none'",
  "manifest-src 'none'",
];

function makeContentSecurityPolicy(host) {
  const connectSources = ["'self'"];
  if (
    typeof host === "string"
    && /^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::[0-9]{1,5})?$/u.test(host)
  ) {
    connectSources.push(`ws://${host}`, `wss://${host}`);
  }
  return [...contentSecurityPolicyBase, `connect-src ${connectSources.join(" ")}`].join("; ");
}

const mimeTypes = new Map([
  [".html", "text/html; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

function integerSetting(name, fallback, minimum, maximum) {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`Invalid ${name}`);
  }
  return value;
}

function base32(bytes) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0;
  let bits = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(value >>> bits) & 31];
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function createId(byteLength = 10) {
  return base32(randomBytes(byteLength));
}

function createToken() {
  return randomBytes(24).toString("base64url");
}

function decodeCanonicalBase64(value, maximumDecodedLength = 4_096) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) return null;
  const decoded = Buffer.from(value, "base64");
  if (decoded.length > maximumDecodedLength || decoded.toString("base64") !== value) return null;
  return decoded;
}

function isPublicKey(value) {
  return decodeCanonicalBase64(value, 32)?.length === 32;
}

function isSessionId(value) {
  return typeof value === "string" && /^[A-Z2-7]{16}$/u.test(value);
}

function isServerId(value) {
  return typeof value === "string" && /^[A-Z2-7]{20,40}$/u.test(value);
}

function isMessageId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{22}$/u.test(value);
}

function isPowToken(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32}$/u.test(value);
}

function isPowNonce(value) {
  return typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/u.test(value);
}

function hasLeadingZeroBits(bytes, difficulty) {
  const fullBytes = Math.floor(difficulty / 8);
  for (let index = 0; index < fullBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  const remaining = difficulty % 8;
  if (remaining === 0) return true;
  return (bytes[fullBytes] & ((0xff << (8 - remaining)) & 0xff)) === 0;
}

function verifyPow(pow) {
  if (!pow || !isPowToken(pow.token) || !isPowNonce(pow.nonce)) return false;
  const challenge = powChallenges.get(pow.token);
  if (!challenge || challenge.used || challenge.expiresAt <= Date.now()) return false;
  if (challenge.attempts >= 5) {
    powChallenges.delete(pow.token);
    return false;
  }

  challenge.attempts += 1;
  const digest = createHash("sha256")
    .update(`${pow.token}:${pow.nonce}`)
    .digest();
  if (!hasLeadingZeroBits(digest, challenge.difficulty)) return false;

  challenge.used = true;
  powChallenges.delete(pow.token);
  return true;
}

function consumeRate(key, capacity, refillPerSecond) {
  const now = Date.now();
  let bucket = rateBuckets.get(key);

  if (!bucket) {
    bucket = { tokens: capacity, updatedAt: now };
    rateBuckets.set(key, bucket);
  }

  const elapsedSeconds = Math.max(0, now - bucket.updatedAt) / 1_000;
  bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSeconds * refillPerSecond);
  bucket.updatedAt = now;

  if (bucket.tokens < 1) return false;
  bucket.tokens -= 1;
  return true;
}

function consumeGlobalAndSessionRate(session, action, globalCapacity, globalRefill, localCapacity, localRefill) {
  return consumeRate(`global:${action}`, globalCapacity, globalRefill)
    && consumeRate(`session:${session.id}:${action}`, localCapacity, localRefill);
}

function onlineSession(sessionId) {
  const session = sessions.get(sessionId);
  return session?.ws?.readyState === WebSocket.OPEN ? session : null;
}

function findChat(firstId, secondId) {
  for (const chat of chats.values()) {
    if ((chat.firstId === firstId && chat.secondId === secondId)
      || (chat.firstId === secondId && chat.secondId === firstId)) {
      return chat;
    }
  }
  return null;
}

function pendingCount(sessionId) {
  let count = 0;
  for (const request of dialogRequests.values()) {
    if (request.fromId === sessionId || request.toId === sessionId) count += 1;
  }
  return count;
}

function setSecurityHeaders(response, host) {
  response.setHeader("Content-Security-Policy", makeContentSecurityPolicy(host));
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("X-DNS-Prefetch-Control", "off");
  response.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  response.setHeader("Origin-Agent-Cluster", "?1");
  response.setHeader("Cache-Control", "no-store, max-age=0");
  response.setHeader("Pragma", "no-cache");
  response.setHeader("Surrogate-Control", "no-store");
  if (process.env.NODE_ENV === "production" || process.env.TLS_CERT_FILE || IS_RAILWAY) {
    response.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
}

function writeJson(response, status, body) {
  const encoded = Buffer.from(JSON.stringify(body));
  response.statusCode = status;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", encoded.length);
  response.end(encoded);
}

function originMatchesHost(request) {
  const origin = request.headers.origin;
  const host = request.headers.host;
  if (typeof origin !== "string" || typeof host !== "string") return false;
  try {
    return new URL(origin).host.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}

async function serveStatic(request, response) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.setHeader("Allow", "GET, HEAD");
    response.statusCode = 405;
    response.end();
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(request.url ?? "/", "http://local").pathname);
  } catch {
    response.statusCode = 400;
    response.end();
    return;
  }

  const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/u, "");
  const filePath = resolve(PUBLIC_ROOT, relativePath);
  if (filePath !== PUBLIC_ROOT && !filePath.startsWith(`${PUBLIC_ROOT}${sep}`)) {
    response.statusCode = 404;
    response.end();
    return;
  }

  try {
    const content = await readFile(filePath);
    response.statusCode = 200;
    response.setHeader("Content-Type", mimeTypes.get(extname(filePath)) ?? "application/octet-stream");
    response.setHeader("Content-Length", content.length);
    if (request.method === "HEAD") response.end();
    else response.end(content);
  } catch {
    response.statusCode = 404;
    response.end();
  }
}

function createPowChallenge(response) {
  if (powChallenges.size >= MAX_POW_CHALLENGES
    || !consumeRate("global:pow:issue", 30, 0.5)) {
    writeJson(response, 429, { error: "rate_limited" });
    return;
  }

  const challenge = {
    token: createToken(),
    difficulty: POW_DIFFICULTY,
    expiresAt: Date.now() + 120_000,
    used: false,
    attempts: 0,
  };
  powChallenges.set(challenge.token, challenge);
  writeJson(response, 200, {
    algorithm: "SHA256",
    token: challenge.token,
    difficulty: challenge.difficulty,
    expiresAt: challenge.expiresAt,
  });
}

async function requestHandler(request, response) {
  setSecurityHeaders(response, request.headers.host);

  let pathname;
  try {
    pathname = new URL(request.url ?? "/", "http://local").pathname;
  } catch {
    response.statusCode = 400;
    response.end();
    return;
  }

  if (pathname === "/api/pow/challenge") {
    if (request.method !== "POST") {
      response.setHeader("Allow", "POST");
      response.statusCode = 405;
      response.end();
      return;
    }
    if (!originMatchesHost(request)) {
      response.statusCode = 403;
      response.end();
      return;
    }
    createPowChallenge(response);
    return;
  }

  await serveStatic(request, response);
}

function sendJson(socket, message) {
  if (socket?.readyState !== WebSocket.OPEN) return false;
  if (socket.bufferedAmount > MAX_BUFFERED_BYTES) {
    socket.close(1013, "Backpressure");
    return false;
  }

  try {
    socket.send(JSON.stringify(message));
    return true;
  } catch {
    return false;
  }
}

function sendError(socket, code, opId) {
  sendJson(socket, { type: "error", code, ...(opId ? { opId } : {}) });
}

function removeChat(chatId, actorId, reason) {
  const chat = chats.get(chatId);
  if (!chat) return;
  chats.delete(chatId);

  for (const sessionId of [chat.firstId, chat.secondId]) {
    const session = onlineSession(sessionId);
    if (!session) continue;
    sendJson(session.ws, {
      type: "chat:ended",
      chatId,
      by: actorId,
      reason,
    });
  }
}

function removeDialogRequest(requestId, reason) {
  const request = dialogRequests.get(requestId);
  if (!request) return;
  dialogRequests.delete(requestId);

  for (const sessionId of [request.fromId, request.toId]) {
    const session = onlineSession(sessionId);
    if (!session) continue;
    sendJson(session.ws, {
      type: "dialog:rejected",
      requestId,
      opId: request.opId,
      reason,
    });
  }
}

function teardownAssociations(session, reason) {
  for (const chat of [...chats.values()]) {
    if (chat.firstId === session.id || chat.secondId === session.id) {
      removeChat(chat.id, session.id, reason);
    }
  }

  for (const request of [...dialogRequests.values()]) {
    if (request.fromId === session.id || request.toId === session.id) {
      removeDialogRequest(request.requestId, reason);
    }
  }
}

function destroySession(session, reason, closeSocket) {
  if (!session || session.destroyed) return;
  session.destroyed = true;
  teardownAssociations(session, reason);
  sessions.delete(session.id);
  if (session.graceTimer) clearTimeout(session.graceTimer);

  if (closeSocket && session.ws?.readyState === WebSocket.OPEN) {
    session.ws.close(1000, "Session ended");
  }
  session.ws = null;
}

function detachSession(session) {
  if (!session || session.destroyed || session.detached) return;
  session.detached = true;
  session.ws = null;
  teardownAssociations(session, "offline");

  session.graceTimer = setTimeout(() => {
    destroySession(session, "expired", false);
  }, GRACE_MS);
  session.graceTimer.unref();
}

function handleCreate(socket, message) {
  if (socket.sessionId) {
    sendError(socket, "CREATE_ONLY", message.opId);
    return;
  }
  if (!isSessionId(message.sessionId) || !isPublicKey(message.identityPublicKey)) {
    sendError(socket, "BAD_REQUEST", message.opId);
    return;
  }
  if (sessions.size >= MAX_SESSIONS || !consumeRate("global:create", 30, 1)) {
    sendError(socket, "RATE_LIMITED", message.opId);
    return;
  }
  if (!verifyPow(message.pow)) {
    sendError(socket, "POW_INVALID", message.opId);
    return;
  }
  if (sessions.has(message.sessionId)) {
    sendError(socket, "SESSION_EXISTS", message.opId);
    return;
  }

  const session = {
    id: message.sessionId,
    identityPublicKey: message.identityPublicKey,
    ws: socket,
    detached: false,
    destroyed: false,
    graceTimer: null,
  };
  sessions.set(session.id, session);
  socket.sessionId = session.id;
  sendJson(socket, {
    type: "ready",
    v: 1,
    sessionId: session.id,
    maxMessageBytes: MAX_MESSAGE_BYTES,
  });
}

function handleSearch(session, message) {
  if (!isSessionId(message.targetId)) {
    sendError(session.ws, "INVALID_SEARCH", message.opId);
    return;
  }
  if (!consumeGlobalAndSessionRate(session, "search", 180, 8, 8, 0.25)) {
    sendError(session.ws, "RATE_LIMITED", message.opId);
    return;
  }

  const target = onlineSession(message.targetId);
  sendJson(session.ws, {
    type: "search:result",
    opId: message.opId,
    found: Boolean(target),
    ...(target ? {
      user: {
        id: target.id,
        identityPublicKey: target.identityPublicKey,
      },
    } : {}),
  });
}

function handleDialogRequest(session, message) {
  if (!isSessionId(message.to) || !isPublicKey(message.ephemeralPublicKey)) {
    sendError(session.ws, "INVALID_DIALOG", message.opId);
    return;
  }
  if (message.to === session.id || findChat(session.id, message.to)) {
    sendError(session.ws, "INVALID_DIALOG", message.opId);
    return;
  }
  if (!consumeGlobalAndSessionRate(session, "dialog-request", 90, 1.5, 3, 0.05)) {
    sendError(session.ws, "RATE_LIMITED", message.opId);
    return;
  }
  if (pendingCount(session.id) >= MAX_PENDING_PER_SESSION) {
    sendError(session.ws, "TOO_MANY_PENDING", message.opId);
    return;
  }

  const target = onlineSession(message.to);
  if (!target) {
    sendError(session.ws, "SESSION_OFFLINE", message.opId);
    return;
  }

  for (const request of dialogRequests.values()) {
    if (request.fromId === session.id && request.toId === target.id) {
      sendError(session.ws, "INVALID_DIALOG", message.opId);
      return;
    }
  }

  const request = {
    requestId: createId(16),
    opId: message.opId,
    fromId: session.id,
    toId: target.id,
    ephemeralPublicKey: message.ephemeralPublicKey,
    createdAt: Date.now(),
  };
  dialogRequests.set(request.requestId, request);

  const delivered = sendJson(target.ws, {
    type: "dialog:request",
    requestId: request.requestId,
    from: {
      id: session.id,
      identityPublicKey: session.identityPublicKey,
    },
    ephemeralPublicKey: request.ephemeralPublicKey,
  });
  if (!delivered) {
    dialogRequests.delete(request.requestId);
    sendError(session.ws, "SESSION_OFFLINE", message.opId);
    return;
  }

  sendJson(session.ws, {
    type: "dialog:request-sent",
    opId: request.opId,
    requestId: request.requestId,
  });
}

function acceptedPayload(chat, request, receiverId, receiverEphemeralPublicKey) {
  const isInitiator = receiverId === request.fromId;
  const peerId = isInitiator ? request.toId : request.fromId;
  return {
    type: "dialog:accepted",
    requestId: request.requestId,
    opId: request.opId,
    chatId: chat.id,
    peerId,
    peerIdentityPublicKey: isInitiator
      ? sessions.get(request.toId).identityPublicKey
      : sessions.get(request.fromId).identityPublicKey,
    peerEphemeralPublicKey: isInitiator
      ? receiverEphemeralPublicKey
      : request.ephemeralPublicKey,
    initiator: isInitiator,
  };
}

function handleDialogAccept(session, message) {
  if (!isServerId(message.requestId) || !isPublicKey(message.ephemeralPublicKey)) {
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }
  if (!consumeGlobalAndSessionRate(session, "dialog-response", 120, 2, 10, 0.2)) {
    sendError(session.ws, "RATE_LIMITED");
    return;
  }

  const request = dialogRequests.get(message.requestId);
  if (!request || request.toId !== session.id) {
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }
  if (chats.size >= MAX_CHATS || findChat(request.fromId, request.toId)) {
    removeDialogRequest(request.requestId, "unavailable");
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }

  const requester = onlineSession(request.fromId);
  if (!requester) {
    dialogRequests.delete(request.requestId);
    sendError(session.ws, "SESSION_OFFLINE");
    return;
  }

  dialogRequests.delete(request.requestId);
  const chat = {
    id: createId(16),
    firstId: request.fromId,
    secondId: request.toId,
  };
  chats.set(chat.id, chat);

  const toAcceptor = sendJson(session.ws, acceptedPayload(chat, request, session.id, message.ephemeralPublicKey));
  const toRequester = sendJson(requester.ws, acceptedPayload(chat, request, requester.id, message.ephemeralPublicKey));
  if (!toAcceptor || !toRequester) removeChat(chat.id, session.id, "offline");
}

function handleDialogReject(session, message) {
  if (!isServerId(message.requestId)
    || !consumeGlobalAndSessionRate(session, "dialog-response", 120, 2, 10, 0.2)) {
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }

  const request = dialogRequests.get(message.requestId);
  if (!request || request.toId !== session.id) {
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }
  dialogRequests.delete(request.requestId);
  sendJson(onlineSession(request.fromId)?.ws, {
    type: "dialog:rejected",
    requestId: request.requestId,
    opId: request.opId,
    reason: "rejected",
  });
}

function handleDialogCancel(session, message) {
  if (!isServerId(message.requestId)
    || !consumeGlobalAndSessionRate(session, "dialog-response", 120, 2, 10, 0.2)) {
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }

  const request = dialogRequests.get(message.requestId);
  if (!request || request.fromId !== session.id) {
    sendError(session.ws, "INVALID_DIALOG");
    return;
  }
  dialogRequests.delete(request.requestId);
  sendJson(onlineSession(request.toId)?.ws, {
    type: "dialog:rejected",
    requestId: request.requestId,
    opId: request.opId,
    reason: "cancelled",
  });
}

function handleChatMessage(session, message) {
  if (!consumeGlobalAndSessionRate(session, "message", 800, 30, 12, 1)) {
    sendError(session.ws, "RATE_LIMITED", message.opId);
    return;
  }

  const chat = chats.get(message.chatId);
  if (!chat || (chat.firstId !== session.id && chat.secondId !== session.id)) {
    sendError(session.ws, "CHAT_NOT_FOUND", message.opId);
    return;
  }
  if (
    message.v !== 1
    || message.algorithm !== "A256GCM"
    || !isMessageId(message.messageId)
    || !Number.isSafeInteger(message.sequence)
    || message.sequence < 1
    || !Number.isSafeInteger(message.plaintextSize)
    || message.plaintextSize < 1
    || message.plaintextSize > MAX_MESSAGE_BYTES
  ) {
    sendError(session.ws, "BAD_REQUEST", message.opId);
    return;
  }

  const nonce = decodeCanonicalBase64(message.nonce, 12);
  const ciphertext = decodeCanonicalBase64(
    message.ciphertext,
    MAX_MESSAGE_BYTES + 16,
  );
  if (
    nonce?.length !== 12
    || ciphertext?.length !== message.plaintextSize + 16
  ) {
    sendError(session.ws, "BAD_REQUEST", message.opId);
    return;
  }

  const peerId = chat.firstId === session.id ? chat.secondId : chat.firstId;
  const peer = onlineSession(peerId);
  if (!peer) {
    removeChat(chat.id, session.id, "offline");
    sendError(session.ws, "PEER_OFFLINE", message.opId);
    return;
  }

  const delivered = sendJson(peer.ws, {
    type: "chat:message",
    v: 1,
    algorithm: "A256GCM",
    senderId: session.id,
    chatId: chat.id,
    messageId: message.messageId,
    sequence: message.sequence,
    plaintextSize: message.plaintextSize,
    nonce: message.nonce,
    ciphertext: message.ciphertext,
  });
  if (!delivered) removeChat(chat.id, session.id, "offline");
}

function handleChatEnd(session, message) {
  if (!consumeGlobalAndSessionRate(session, "chat-end", 120, 3, 30, 1)) {
    sendError(session.ws, "RATE_LIMITED", message.opId);
    return;
  }
  const chat = chats.get(message.chatId);
  if (!chat || (chat.firstId !== session.id && chat.secondId !== session.id)) {
    sendError(session.ws, "CHAT_NOT_FOUND", message.opId);
    return;
  }
  removeChat(chat.id, session.id, "ended");
}

function handleChatCryptoError(session, message) {
  const chat = chats.get(message.chatId);
  if (!chat || (chat.firstId !== session.id && chat.secondId !== session.id)) return;
  removeChat(chat.id, session.id, "crypto-error");
}

function routeMessage(socket, message) {
  if (!message || typeof message.type !== "string") {
    sendError(socket, "BAD_REQUEST");
    socket.close(1008, "Invalid message");
    return;
  }
  if (message.type === "create") {
    handleCreate(socket, message);
    return;
  }

  const session = socket.sessionId ? sessions.get(socket.sessionId) : null;
  if (!session || session.ws !== socket || session.detached) {
    sendError(socket, "SESSION_NOT_FOUND");
    socket.close(1008, "No session");
    return;
  }

  switch (message.type) {
    case "search":
      handleSearch(session, message);
      break;
    case "dialog:request":
      handleDialogRequest(session, message);
      break;
    case "dialog:accept":
      handleDialogAccept(session, message);
      break;
    case "dialog:reject":
      handleDialogReject(session, message);
      break;
    case "dialog:cancel":
      handleDialogCancel(session, message);
      break;
    case "chat:message":
      handleChatMessage(session, message);
      break;
    case "chat:end":
      handleChatEnd(session, message);
      break;
    case "chat:crypto-error":
      handleChatCryptoError(session, message);
      break;
    case "session:leave":
      destroySession(session, "ended", true);
      break;
    default:
      sendError(socket, "BAD_REQUEST", message.opId);
      break;
  }
}

function attachWebSocket(socket) {
  socket.isAlive = true;
  socket.on("pong", () => {
    socket.isAlive = true;
  });

  socket.on("message", (data, isBinary) => {
    if (isBinary) {
      socket.close(1003, "Binary unsupported");
      return;
    }

    let message;
    try {
      message = JSON.parse(data.toString());
    } catch {
      sendError(socket, "BAD_REQUEST");
      socket.close(1007, "Invalid JSON");
      return;
    }
    routeMessage(socket, message);
  });

  socket.on("close", () => {
    if (socket.sessionId) detachSession(sessions.get(socket.sessionId));
  });
  socket.on("error", () => {
    // close handles cleanup; no connection metadata is read or retained.
  });
}

const webSocketServer = new WebSocketServer({
  noServer: true,
  maxPayload: MAX_WS_PAYLOAD,
  perMessageDeflate: false,
});

webSocketServer.on("connection", (socket) => {
  attachWebSocket(socket);
});
webSocketServer.on("error", () => {
  // Keep operational details out of stdout/stderr.
});

function attachUpgradeHandler(httpServer) {
  httpServer.on("upgrade", (request, socket, head) => {
    let pathname;
    try {
      pathname = new URL(request.url ?? "/", "http://local").pathname;
    } catch {
      socket.destroy();
      return;
    }

    if (
      pathname !== "/ws"
      || !originMatchesHost(request)
      || webSocketServer.clients.size >= MAX_SESSIONS
    ) {
      socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
      socket.destroy();
      return;
    }

    webSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
      webSocketServer.emit("connection", webSocket, request);
    });
  });
}

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [token, challenge] of powChallenges) {
    if (challenge.expiresAt <= now || challenge.used) powChallenges.delete(token);
  }
  for (const [requestId, request] of dialogRequests) {
    if (request.createdAt + SESSION_GRACE_SECONDS * 1_000 <= now) {
      removeDialogRequest(requestId, "expired");
    }
  }
  for (const [key, bucket] of rateBuckets) {
    if (bucket.updatedAt + 10 * 60_000 <= now) rateBuckets.delete(key);
  }
}, 15_000);
cleanupTimer.unref();

const heartbeatTimer = setInterval(() => {
  for (const socket of webSocketServer.clients) {
    if (socket.readyState !== WebSocket.OPEN) continue;
    if (!socket.isAlive) {
      socket.terminate();
      continue;
    }
    socket.isAlive = false;
    socket.ping();
  }
}, 30_000);
heartbeatTimer.unref();

async function createServer() {
  const certificateFile = process.env.TLS_CERT_FILE;
  const keyFile = process.env.TLS_KEY_FILE;
  const hasCertificate = Boolean(certificateFile);
  const hasKey = Boolean(keyFile);
  if (hasCertificate !== hasKey) throw new Error("Both TLS_CERT_FILE and TLS_KEY_FILE are required");

  const loopbackHosts = new Set(["127.0.0.1", "localhost", "::1"]);
  const localDevelopment = process.env.NODE_ENV !== "production" && loopbackHosts.has(HOST);
  const plaintextProxyAllowed = process.env.ALLOW_PLAINTEXT_LOCAL === "1"
    && loopbackHosts.has(HOST);
  if (!hasCertificate && !localDevelopment && !plaintextProxyAllowed && !IS_RAILWAY) {
    throw new Error("TLS is required outside loopback development or a trusted platform proxy");
  }

  if (hasCertificate) {
    const [certificate, key] = await Promise.all([
      readFile(certificateFile),
      readFile(keyFile),
    ]);
    return https.createServer({ cert: certificate, key }, requestHandler);
  }
  return http.createServer(requestHandler);
}

function start() {
  createServer()
    .then((httpServer) => {
      httpServer.on("clientError", (_error, socket) => socket.destroy());
      httpServer.on("error", () => process.exit(1));
      attachUpgradeHandler(httpServer);
      httpServer.listen(PORT, HOST);
    })
    .catch(() => process.exit(1));
}

start();
