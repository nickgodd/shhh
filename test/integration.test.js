import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import {
  buildOrderedChatContext,
  createEphemeralKeyPair,
  createIdentityKeyPair,
  createMessageId,
  decryptChatMessage,
  deriveChatContext,
  encryptChatMessage,
} from "../public/js/crypto.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function availablePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve) => server.close(resolve));
  if (!port) throw new Error("Could not allocate a test port");
  return port;
}

function solvePow(token, difficulty) {
  for (let nonce = 0; ; nonce += 1) {
    const digest = createHash("sha256").update(`${token}:${nonce}`).digest();
    let valid = true;
    for (let bit = 0; bit < difficulty; bit += 1) {
      if ((digest[bit >> 3] & (0x80 >> (bit & 7))) !== 0) {
        valid = false;
        break;
      }
    }
    if (valid) return String(nonce);
  }
}

class TestClient {
  constructor(origin, webSocketUrl) {
    this.origin = origin;
    this.socket = new WebSocket(webSocketUrl, { origin });
    this.messages = [];
    this.waiters = new Set();
    this.socket.on("message", (raw) => {
      const message = JSON.parse(raw.toString());
      for (const waiter of this.waiters) {
        if (waiter.predicate(message)) {
          clearTimeout(waiter.timer);
          this.waiters.delete(waiter);
          waiter.resolve(message);
          return;
        }
      }
      this.messages.push(message);
    });
  }

  async open() {
    if (this.socket.readyState === WebSocket.OPEN) return;
    await Promise.race([
      once(this.socket, "open"),
      once(this.socket, "error").then(([error]) => Promise.reject(error)),
    ]);
  }

  send(message) {
    this.socket.send(JSON.stringify(message));
  }

  waitFor(predicate, label) {
    const queuedIndex = this.messages.findIndex(predicate);
    if (queuedIndex >= 0) {
      return Promise.resolve(this.messages.splice(queuedIndex, 1)[0]);
    }

    return new Promise((resolve, reject) => {
      const waiter = { predicate, resolve, timer: null };
      waiter.timer = setTimeout(() => {
        this.waiters.delete(waiter);
        reject(new Error(`Timed out waiting for ${label}`));
      }, 5_000);
      this.waiters.add(waiter);
    });
  }

  close() {
    this.socket.close();
  }
}

async function waitForServer(origin, child) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error("Test server exited during startup");
    try {
      const response = await fetch(origin, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {
      // Retry until the child binds the port.
    }
    await delay(25);
  }
  throw new Error("Test server did not start");
}

async function registerClient(origin, webSocketUrl, id) {
  const client = new TestClient(origin, webSocketUrl);
  await client.open();
  const identityKeyPair = await createIdentityKeyPair();
  const response = await fetch(`${origin}/api/pow/challenge`, {
    method: "POST",
    headers: { Origin: origin },
  });
  assert.equal(response.status, 200);
  const challenge = await response.json();
  client.send({
    type: "create",
    opId: "create",
    sessionId: id,
    identityPublicKey: identityKeyPair.publicKey,
    pow: {
      token: challenge.token,
      nonce: solvePow(challenge.token, challenge.difficulty),
    },
  });
  const ready = await client.waitFor((message) => message.type === "ready", `${id} ready`);
  assert.equal(ready.sessionId, id);
  return { client, identityKeyPair, id };
}

async function search(client, targetId) {
  const opId = createMessageId();
  const resultPromise = client.waitFor(
    (message) => message.type === "search:result" && message.opId === opId,
    "search result",
  );
  client.send({ type: "search", opId, targetId });
  return resultPromise;
}

async function requestDialog(alice, bob, targetId) {
  const opId = createMessageId();
  const sentPromise = alice.client.waitFor(
    (message) => message.type === "dialog:request-sent" && message.opId === opId,
    "dialog request acknowledgement",
  );
  const incomingPromise = bob.client.waitFor(
    (message) => message.type === "dialog:request",
    "incoming dialog request",
  );
  const ephemeralKeyPair = await createEphemeralKeyPair();
  alice.client.send({
    type: "dialog:request",
    opId,
    to: targetId,
    ephemeralPublicKey: ephemeralKeyPair.publicKey,
  });
  const [sent, incoming] = await Promise.all([sentPromise, incomingPromise]);
  assert.equal(sent.requestId, incoming.requestId);
  return { opId, request: incoming, ephemeralKeyPair };
}

function applyResolvedEvent(foundPeers, clientId, message) {
  if (message.type === "dialog:resolved") foundPeers.delete(clientId);
}

test("two shhh clients derive one key, exchange messages and clear found state", { timeout: 30_000 }, async (context) => {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const webSocketUrl = `ws://127.0.0.1:${port}/ws`;
  const server = spawn(process.execPath, ["server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      POW_DIFFICULTY: "12",
    },
    stdio: "ignore",
  });

  context.after(async () => {
    if (server.exitCode === null) {
      server.kill();
      await Promise.race([once(server, "exit"), delay(2_000)]);
    }
  });

  await waitForServer(origin, server);
  const aliceId = "AAAAAAAAAAAAAAAA";
  const bobId = "BBBBBBBBBBBBBBBB";
  const alice = await registerClient(origin, webSocketUrl, aliceId);
  const bob = await registerClient(origin, webSocketUrl, bobId);
  context.after(() => {
    alice.client.close();
    bob.client.close();
  });

  const foundPeers = new Map([
    [aliceId, bobId],
    [bobId, aliceId],
  ]);
  const found = await search(alice.client, bobId.toLowerCase());
  assert.equal(found.found, true);
  assert.equal(found.user.id, bobId);

  const dialog = await requestDialog(alice, bob, bobId.toLowerCase());
  const bobEphemeralKeyPair = await createEphemeralKeyPair();
  const aliceAcceptedPromise = alice.client.waitFor(
    (message) => message.type === "dialog:accepted" && message.initiator === true,
    "Alice accepted dialog",
  );
  const bobAcceptedPromise = bob.client.waitFor(
    (message) => message.type === "dialog:accepted" && message.initiator === false,
    "Bob accepted dialog",
  );
  const aliceResolvedPromise = alice.client.waitFor(
    (message) => message.type === "dialog:resolved" && message.outcome === "accepted",
    "Alice dialog resolved",
  );
  const bobResolvedPromise = bob.client.waitFor(
    (message) => message.type === "dialog:resolved" && message.outcome === "accepted",
    "Bob dialog resolved",
  );
  bob.client.send({
    type: "dialog:accept",
    requestId: dialog.request.requestId,
    ephemeralPublicKey: bobEphemeralKeyPair.publicKey,
  });
  const [aliceAccepted, bobAccepted, aliceResolved, bobResolved] = await Promise.all([
    aliceAcceptedPromise,
    bobAcceptedPromise,
    aliceResolvedPromise,
    bobResolvedPromise,
  ]);
  assert.equal(aliceAccepted.chatId, bobAccepted.chatId);
  applyResolvedEvent(foundPeers, aliceId, aliceResolved);
  applyResolvedEvent(foundPeers, bobId, bobResolved);
  assert.equal(foundPeers.size, 0);

  const alicePublicBefore = dialog.ephemeralKeyPair.publicKey;
  const bobPublicBefore = bobEphemeralKeyPair.publicKey;
  const aliceContextBytes = buildOrderedChatContext({
    chatId: aliceAccepted.chatId,
    localId: aliceId,
    localEphemeralPublicKey: dialog.ephemeralKeyPair.publicKey,
    peerId: bobId,
    peerEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
  });
  const bobContextBytes = buildOrderedChatContext({
    chatId: bobAccepted.chatId,
    localId: bobId,
    localEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
    peerId: aliceId,
    peerEphemeralPublicKey: dialog.ephemeralKeyPair.publicKey,
  });
  assert.deepEqual(aliceContextBytes, bobContextBytes);

  const aliceContext = await deriveChatContext({
    chatId: aliceAccepted.chatId,
    localId: aliceId,
    peerId: bobId,
    localPrivateKey: dialog.ephemeralKeyPair.privateKey,
    localEphemeralPublicKey: dialog.ephemeralKeyPair.publicKey,
    peerEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
  });
  const bobContext = await deriveChatContext({
    chatId: bobAccepted.chatId,
    localId: bobId,
    peerId: aliceId,
    localPrivateKey: bobEphemeralKeyPair.privateKey,
    localEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
    peerEphemeralPublicKey: dialog.ephemeralKeyPair.publicKey,
  });
  assert.equal(aliceContext.fingerprint, bobContext.fingerprint);
  const aliceChat = {
    id: aliceAccepted.chatId,
    localId: aliceId,
    encryptionKey: aliceContext.encryptionKey,
  };
  const bobChat = {
    id: bobAccepted.chatId,
    localId: bobId,
    encryptionKey: bobContext.encryptionKey,
  };

  const repeatedAliceContext = await deriveChatContext({
    chatId: aliceAccepted.chatId,
    localId: aliceId,
    peerId: bobId,
    localPrivateKey: dialog.ephemeralKeyPair.privateKey,
    localEphemeralPublicKey: dialog.ephemeralKeyPair.publicKey,
    peerEphemeralPublicKey: bobEphemeralKeyPair.publicKey,
  });
  assert.equal(repeatedAliceContext.fingerprint, aliceContext.fingerprint);
  assert.equal(dialog.ephemeralKeyPair.publicKey, alicePublicBefore);
  assert.equal(bobEphemeralKeyPair.publicKey, bobPublicBefore);

  const aliceToBob = await encryptChatMessage(
    aliceChat,
    "сообщение от A",
    1,
    createMessageId(),
  );
  assert.equal(
    await decryptChatMessage(bobChat, aliceToBob, aliceId),
    "сообщение от A",
  );
  const bobDeliveryPromise = bob.client.waitFor(
    (message) => message.type === "chat:message",
    "Alice to Bob message",
  );
  alice.client.send({ type: "chat:message", ...aliceToBob });
  const bobDelivery = await bobDeliveryPromise;
  let aliceMessage;
  try {
    aliceMessage = await decryptChatMessage(bobChat, bobDelivery, aliceId);
  } catch (error) {
    throw new Error(`Alice to Bob decryption failed: ${error.message}`);
  }
  assert.equal(aliceMessage, "сообщение от A");

  const bobToAlice = await encryptChatMessage(
    bobChat,
    "сообщение от B",
    1,
    createMessageId(),
  );
  const aliceDeliveryPromise = alice.client.waitFor(
    (message) => message.type === "chat:message",
    "Bob to Alice message",
  );
  bob.client.send({ type: "chat:message", ...bobToAlice });
  const aliceDelivery = await aliceDeliveryPromise;
  let bobMessage;
  try {
    bobMessage = await decryptChatMessage(aliceChat, aliceDelivery, bobId);
  } catch (error) {
    throw new Error(`Bob to Alice decryption failed: ${error.message}`);
  }
  assert.equal(bobMessage, "сообщение от B");

  foundPeers.set(aliceId, bobId);
  foundPeers.set(bobId, aliceId);
  const aliceEndedPromise = alice.client.waitFor(
    (message) => message.type === "chat:ended",
    "Alice chat ended",
  );
  const bobEndedPromise = bob.client.waitFor(
    (message) => message.type === "chat:ended",
    "Bob chat ended",
  );
  const aliceEndResolvedPromise = alice.client.waitFor(
    (message) => message.type === "dialog:resolved" && message.outcome === "ended",
    "Alice end resolved",
  );
  const bobEndResolvedPromise = bob.client.waitFor(
    (message) => message.type === "dialog:resolved" && message.outcome === "ended",
    "Bob end resolved",
  );
  alice.client.send({ type: "chat:end", chatId: aliceAccepted.chatId });
  const [aliceEnded, bobEnded, aliceEndResolved, bobEndResolved] = await Promise.all([
    aliceEndedPromise,
    bobEndedPromise,
    aliceEndResolvedPromise,
    bobEndResolvedPromise,
  ]);
  assert.equal(aliceEnded.chatId, bobEnded.chatId);
  applyResolvedEvent(foundPeers, aliceId, aliceEndResolved);
  applyResolvedEvent(foundPeers, bobId, bobEndResolved);
  assert.equal(foundPeers.size, 0);

  foundPeers.set(aliceId, bobId);
  foundPeers.set(bobId, aliceId);
  assert.equal((await search(alice.client, bobId.toLowerCase())).found, true);
  const rejectedDialog = await requestDialog(alice, bob, bobId);
  const aliceRejectedPromise = alice.client.waitFor(
    (message) => message.type === "dialog:rejected",
    "Alice dialog rejected",
  );
  const aliceRejectResolvedPromise = alice.client.waitFor(
    (message) => message.type === "dialog:resolved" && message.outcome === "rejected",
    "Alice rejection resolved",
  );
  const bobRejectResolvedPromise = bob.client.waitFor(
    (message) => message.type === "dialog:resolved" && message.outcome === "rejected",
    "Bob rejection resolved",
  );
  bob.client.send({ type: "dialog:reject", requestId: rejectedDialog.request.requestId });
  const [aliceRejected, aliceRejectResolved, bobRejectResolved] = await Promise.all([
    aliceRejectedPromise,
    aliceRejectResolvedPromise,
    bobRejectResolvedPromise,
  ]);
  assert.equal(aliceRejected.requestId, rejectedDialog.request.requestId);
  applyResolvedEvent(foundPeers, aliceId, aliceRejectResolved);
  applyResolvedEvent(foundPeers, bobId, bobRejectResolved);
  assert.equal(foundPeers.size, 0);
});
