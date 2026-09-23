const textEncoder = new TextEncoder();
const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CHAT_KDF_CONTEXT = "shhh-chat-v1";
const CHAT_KDF_OUTPUT_BYTES = 52;

export const MAX_MESSAGE_BYTES = 2048;

function subtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto API недоступен. Откройте приложение в HTTPS-контексте.");
  }
  return globalThis.crypto.subtle;
}

export function randomBytes(length) {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function bytesToBase64(bytes) {
  const parts = [];
  const chunkSize = 0x8000;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
    let binary = "";
    for (const byte of chunk) binary += String.fromCharCode(byte);
    parts.push(btoa(binary));
  }

  return parts.join("");
}

export function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export function randomBase32(byteLength = 10) {
  const bytes = randomBytes(byteLength);
  let value = 0;
  let bits = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      output += base32Alphabet[(value >>> bits) & 31];
    }
  }

  if (bits > 0) output += base32Alphabet[(value << (5 - bits)) & 31];
  return output;
}

export function createSessionId() {
  return randomBase32(10);
}

export function createMessageId() {
  return bytesToBase64Url(randomBytes(16));
}

async function generateX25519KeyPair() {
  try {
    const keyPair = await subtle().generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return {
      privateKey: keyPair.privateKey,
      publicKey: await exportX25519PublicKey(keyPair.publicKey),
    };
  } catch {
    throw new Error("Браузер не поддерживает Web Crypto X25519. Обновите браузер.");
  }
}

async function exportX25519PublicKey(publicKey) {
  const raw = new Uint8Array(await subtle().exportKey("raw", publicKey));
  if (raw.length !== 32) throw new Error("Некорректный публичный ключ X25519.");
  return bytesToBase64(raw);
}

async function importX25519PublicKey(encoded) {
  const raw = base64ToBytes(encoded);
  if (raw.length !== 32) throw new Error("Некорректный публичный ключ X25519.");
  return subtle().importKey("raw", raw, { name: "X25519" }, false, []);
}

export async function createIdentityKeyPair() {
  const ephemeral = await generateX25519KeyPair();
  return {
    privateKey: ephemeral.privateKey,
    publicKey: ephemeral.publicKey,
  };
}

export async function createEphemeralKeyPair() {
  return generateX25519KeyPair();
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function encodeLength(length) {
  if (!Number.isSafeInteger(length) || length < 0 || length > 0xffff_ffff) {
    throw new Error("Некорректная длина данных.");
  }
  return new Uint8Array([
    (length >>> 24) & 0xff,
    (length >>> 16) & 0xff,
    (length >>> 8) & 0xff,
    length & 0xff,
  ]);
}

function compareBytes(left, right) {
  const length = Math.min(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.byteLength - right.byteLength;
}

export function buildOrderedChatContext({
  chatId,
  localId,
  localEphemeralPublicKey,
  peerId,
  peerEphemeralPublicKey,
}) {
  const localPublicKeyBytes = base64ToBytes(localEphemeralPublicKey);
  const peerPublicKeyBytes = base64ToBytes(peerEphemeralPublicKey);
  if (localPublicKeyBytes.length !== 32 || peerPublicKeyBytes.length !== 32) {
    throw new Error("Некорректный публичный ключ X25519.");
  }

  const localIdBytes = textEncoder.encode(localId);
  const peerIdBytes = textEncoder.encode(peerId);
  const endpoints = [
    { id: localIdBytes, publicKey: localPublicKeyBytes },
    { id: peerIdBytes, publicKey: peerPublicKeyBytes },
  ].sort((left, right) => (
    compareBytes(left.publicKey, right.publicKey)
    || compareBytes(left.id, right.id)
  ));

  const label = textEncoder.encode(CHAT_KDF_CONTEXT);
  const chatIdBytes = textEncoder.encode(chatId);
  const parts = [
    encodeLength(label.length),
    label,
    encodeLength(chatIdBytes.length),
    chatIdBytes,
    new Uint8Array([endpoints.length]),
  ];
  for (const endpoint of endpoints) {
    parts.push(
      encodeLength(endpoint.id.byteLength),
      endpoint.id,
      encodeLength(endpoint.publicKey.byteLength),
      endpoint.publicKey,
    );
  }
  return concatBytes(...parts);
}

export async function deriveChatContext({
  chatId,
  localId,
  peerId,
  localPrivateKey,
  localEphemeralPublicKey,
  peerEphemeralPublicKey,
}) {
  if (localId === peerId) throw new Error("Нельзя создать чат с самой собой.");

  const peerPublicKey = await importX25519PublicKey(peerEphemeralPublicKey);
  const material = buildOrderedChatContext({
    chatId,
    localId,
    localEphemeralPublicKey,
    peerId,
    peerEphemeralPublicKey,
  });
  const salt = new Uint8Array(await subtle().digest("SHA-256", material));
  const sharedSecret = new Uint8Array(
    await subtle().deriveBits(
      { name: "X25519", public: peerPublicKey },
      localPrivateKey,
      256,
    ),
  );

  if (sharedSecret.every((byte) => byte === 0)) {
    throw new Error("ECDH вернул неприемлемый общий секрет.");
  }

  const hkdfKey = await subtle().importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
  const expanded = new Uint8Array(
    await subtle().deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info: concatBytes(material, textEncoder.encode("key-and-fingerprint")),
      },
      hkdfKey,
      CHAT_KDF_OUTPUT_BYTES * 8,
    ),
  );

  const encryptionKeyBytes = expanded.slice(0, 32);
  const fingerprintBytes = expanded.slice(32, 52);
  const fingerprint = formatFingerprint(fingerprintBytes);

  try {
    const encryptionKey = await subtle().importKey(
      "raw",
      encryptionKeyBytes,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    return { encryptionKey, fingerprint };
  } finally {
    sharedSecret.fill(0);
    expanded.fill(0);
    encryptionKeyBytes.fill(0);
    fingerprintBytes.fill(0);
  }
}

function formatFingerprint(bytes) {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/gu).join(" ");
}

function messageAad({ chatId, senderId, messageId, sequence, plaintextSize }) {
  return textEncoder.encode(
    JSON.stringify({
      v: 1,
      chatId,
      senderId,
      messageId,
      sequence,
      plaintextSize,
    }),
  );
}

export async function encryptChatMessage(chat, plaintext, sequence, messageId) {
  const plaintextBytes = textEncoder.encode(plaintext);
  const plaintextSize = plaintextBytes.byteLength;

  if (plaintextSize < 1 || plaintextSize > MAX_MESSAGE_BYTES) {
    throw new Error("Сообщение должно быть от 1 байта до 2 КБ.");
  }

  const nonce = randomBytes(12);
  const aad = messageAad({
    chatId: chat.id,
    senderId: chat.localId,
    messageId,
    sequence,
    plaintextSize,
  });
  const ciphertext = new Uint8Array(
    await subtle().encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aad,
        tagLength: 128,
      },
      chat.encryptionKey,
      plaintextBytes,
    ),
  );

  return {
    v: 1,
    algorithm: "A256GCM",
    chatId: chat.id,
    messageId,
    sequence,
    plaintextSize,
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext),
  };
}

export async function decryptChatMessage(chat, envelope, authenticatedSenderId) {
  if (envelope.v !== 1 || envelope.algorithm !== "A256GCM") {
    throw new Error("Неподдерживаемый формат сообщения.");
  }

  const nonce = base64ToBytes(envelope.nonce);
  const ciphertext = base64ToBytes(envelope.ciphertext);
  if (nonce.length !== 12 || ciphertext.length !== envelope.plaintextSize + 16) {
    throw new Error("Некорректный размер зашифрованного сообщения.");
  }

  const aad = messageAad({
    chatId: chat.id,
    senderId: authenticatedSenderId,
    messageId: envelope.messageId,
    sequence: envelope.sequence,
    plaintextSize: envelope.plaintextSize,
  });
  const plaintext = new Uint8Array(
    await subtle().decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: aad,
        tagLength: 128,
      },
      chat.encryptionKey,
      ciphertext,
    ),
  );

  if (plaintext.byteLength !== envelope.plaintextSize || plaintext.byteLength > MAX_MESSAGE_BYTES) {
    throw new Error("Сообщение превышает допустимый размер.");
  }

  return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}

function hasLeadingZeroBits(bytes, difficulty) {
  const fullBytes = Math.floor(difficulty / 8);
  for (let index = 0; index < fullBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }

  const remainingBits = difficulty % 8;
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (bytes[fullBytes] & mask) === 0;
}

export async function solvePow({ token, difficulty }, signal) {
  if (!Number.isInteger(difficulty) || difficulty < 12 || difficulty > 20) {
    throw new Error("Некорректная сложность проверки.");
  }

  const startedAt = performance.now();
  const prefix = `${token}:`;
  let nonce = 0;

  for (;;) {
    const digest = new Uint8Array(
      await subtle().digest("SHA-256", textEncoder.encode(`${prefix}${nonce}`)),
    );
    if (hasLeadingZeroBits(digest, difficulty)) return String(nonce);

    nonce += 1;
    if ((nonce & 255) === 0) {
      await new Promise((resolve) => setTimeout(resolve, 0));
      if (signal?.aborted) throw new DOMException("Проверка отменена.", "AbortError");
      if (performance.now() - startedAt > 120_000) {
        throw new Error("Проверка заняла слишком много времени. Попробуйте ещё раз.");
      }
    }
  }
}
