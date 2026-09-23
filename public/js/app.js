import {
  MAX_MESSAGE_BYTES,
  createEphemeralKeyPair,
  createIdentityKeyPair,
  createMessageId,
  createSessionId,
  decryptChatMessage,
  deriveChatContext,
  encryptChatMessage,
  solvePow,
} from "./crypto.js";

const SESSION_ID_PATTERN = /^[A-Z2-7]{16}$/u;
const textEncoder = new TextEncoder();
const timeFormatter = new Intl.DateTimeFormat("ru-RU", {
  hour: "2-digit",
  minute: "2-digit",
});

const elements = {
  startScreen: document.querySelector("#startScreen"),
  startStatus: document.querySelector("#startStatus"),
  createSessionButton: document.querySelector("#createSessionButton"),
  workspace: document.querySelector("#workspace"),
  profileButton: document.querySelector("#profileButton"),
  profilePanel: document.querySelector("#profilePanel"),
  profileId: document.querySelector("#profileId"),
  profileKey: document.querySelector("#profileKey"),
  exitButton: document.querySelector("#exitButton"),
  searchForm: document.querySelector("#searchForm"),
  searchInput: document.querySelector("#searchInput"),
  searchResult: document.querySelector("#searchResult"),
  searchResultId: document.querySelector("#searchResultId"),
  requestButton: document.querySelector("#requestButton"),
  incomingSection: document.querySelector("#incomingSection"),
  incomingList: document.querySelector("#incomingList"),
  outgoingSection: document.querySelector("#outgoingSection"),
  outgoingList: document.querySelector("#outgoingList"),
  chatList: document.querySelector("#chatList"),
  emptyChatList: document.querySelector("#emptyChatList"),
  chatTitle: document.querySelector("#chatTitle"),
  chatState: document.querySelector("#chatState"),
  chatMenuButton: document.querySelector("#chatMenuButton"),
  chatMenu: document.querySelector("#chatMenu"),
  endChatButton: document.querySelector("#endChatButton"),
  backButton: document.querySelector("#backButton"),
  fingerprintBar: document.querySelector("#fingerprintBar"),
  fingerprint: document.querySelector("#fingerprint"),
  messages: document.querySelector("#messages"),
  emptyChat: document.querySelector("#emptyChat"),
  messageForm: document.querySelector("#messageForm"),
  messageInput: document.querySelector("#messageInput"),
  byteCounter: document.querySelector("#byteCounter"),
  sendButton: document.querySelector("#sendButton"),
  requestDialog: document.querySelector("#requestDialog"),
  requestDialogId: document.querySelector("#requestDialogId"),
  acceptRequestButton: document.querySelector("#acceptRequestButton"),
  rejectRequestButton: document.querySelector("#rejectRequestButton"),
  toast: document.querySelector("#toast"),
};

const state = {
  starting: false,
  socket: null,
  pendingRegistration: null,
  session: null,
  chats: new Map(),
  incoming: new Map(),
  outgoing: new Map(),
  accepting: new Map(),
  selectedChatId: null,
  foundUser: null,
  searchOperationId: null,
  activeRequestId: null,
  sendingChatIds: new Set(),
};

let toastTimer = 0;

function normalizeSessionId(value) {
  return value.trim().toUpperCase().replace(/\s+/gu, "");
}

function setStartBusy(busy) {
  state.starting = busy;
  elements.createSessionButton.disabled = busy;
}

function showToast(message) {
  window.clearTimeout(toastTimer);
  elements.toast.textContent = message;
  elements.toast.hidden = false;
  toastTimer = window.setTimeout(() => {
    elements.toast.hidden = true;
  }, 4200);
}

function errorText(code) {
  const messages = {
    BAD_REQUEST: "Некорректный запрос.",
    CREATE_ONLY: "Сначала создайте сессию.",
    POW_INVALID: "Проверка защиты не пройдена. Попробуйте ещё раз.",
    RATE_LIMITED: "Слишком много действий. Подождите немного.",
    SESSION_EXISTS: "Этот идентификатор уже активен.",
    SESSION_NOT_FOUND: "Сессия больше не активна.",
    SESSION_OFFLINE: "Собеседник уже не в сети.",
    INVALID_ID: "Идентификатор должен содержать 16 символов base32.",
    INVALID_SEARCH: "Введите корректный идентификатор.",
    INVALID_DIALOG: "Запрос диалога недействителен.",
    TOO_MANY_PENDING: "Слишком много ожидающих запросов.",
    CHAT_NOT_FOUND: "Чат уже завершён.",
    PEER_OFFLINE: "Собеседник не в сети. Сообщение не доставлено.",
    RATE_LIMIT: "Слишком много сообщений. Подождите немного.",
  };

  return messages[code] ?? "Действие не выполнено. Попробуйте ещё раз.";
}

function createElement(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function isOpenSocket(socket = state.socket) {
  return socket?.readyState === WebSocket.OPEN;
}

function sendProtocol(message) {
  if (!isOpenSocket()) {
    showToast("Нет соединения с сервером.");
    return false;
  }

  try {
    state.socket.send(JSON.stringify(message));
    return true;
  } catch {
    return false;
  }
}

async function requestPowChallenge() {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 10_000);
  const acceptable = ["application/json"];

  try {
    const response = await fetch("/api/pow/challenge", {
      method: "POST",
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
      headers: { Accept: acceptable.join(", ") },
      signal: controller.signal,
    });

    if (!response.ok) {
      if (response.status === 429) throw new Error("Слишком много попыток. Подождите немного.");
      throw new Error("Сервер проверки недоступен.");
    }

    const challenge = await response.json();
    if (
      typeof challenge.token !== "string"
      || !Number.isInteger(challenge.difficulty)
      || challenge.algorithm !== "SHA256"
    ) {
      throw new Error("Сервер вернул некорректную проверку.");
    }
    return challenge;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("Сервер не ответил вовремя.");
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function waitForSocketOpen(socket) {
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      cleanup();
      reject(new Error("Не удалось открыть защищённое соединение."));
    }, 10_000);

    const onOpen = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      reject(new Error("Не удалось открыть защищённое соединение."));
    };
    const cleanup = () => {
      window.clearTimeout(timeout);
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("error", onError);
    };

    socket.addEventListener("open", onOpen, { once: true });
    socket.addEventListener("error", onError, { once: true });
  });
}

function installSocketHandlers(socket) {
  socket.addEventListener("message", (event) => {
    if (state.socket !== socket || typeof event.data !== "string") return;

    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      socket.close(1003, "Bad frame");
      return;
    }

    if (!message || typeof message.type !== "string") return;

    if (state.pendingRegistration && message.type === "ready") {
      const pending = state.pendingRegistration;
      state.pendingRegistration = null;
      pending.resolve(message);
      return;
    }

    if (state.pendingRegistration && message.type === "error" && message.opId === "create") {
      const pending = state.pendingRegistration;
      state.pendingRegistration = null;
      pending.reject(new Error(errorText(message.code)));
      return;
    }

    void routeServerMessage(message);
  });

  socket.addEventListener("close", () => {
    if (state.socket !== socket) return;
    state.socket = null;

    if (state.pendingRegistration) {
      const pending = state.pendingRegistration;
      state.pendingRegistration = null;
      pending.reject(new Error("Соединение закрыто до завершения регистрации."));
      return;
    }

    resetToStart("Соединение завершено. Все чаты удалены — создайте новую сессию.");
  });

  socket.addEventListener("error", () => {
    // The close event performs cleanup. Browser error details may contain
    // implementation-specific information and are intentionally not logged.
  });
}

async function registerSocket({ sessionId, identityKeyPair, powSolution, challenge }) {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);

  await waitForSocketOpen(socket);
  state.socket = socket;
  installSocketHandlers(socket);

  const registration = new Promise((resolve, reject) => {
    state.pendingRegistration = { resolve, reject };
  });
  const timeout = new Promise((_, reject) => {
    window.setTimeout(() => reject(new Error("Сервер не подтвердил новую сессию.")), 10_000);
  });

  const sent = sendProtocol({
    type: "create",
    opId: "create",
    sessionId,
    identityPublicKey: identityKeyPair.publicKey,
    pow: {
      token: challenge.token,
      nonce: powSolution,
    },
  });
  if (!sent) throw new Error("Соединение закрылось во время регистрации.");

  const ready = await Promise.race([registration, timeout]);
  if (ready.sessionId !== sessionId) throw new Error("Сервер подтвердил другой идентификатор.");
  return ready;
}

async function createSession() {
  if (state.starting) return;

  setStartBusy(true);
  elements.startStatus.textContent = "Получаем проверку…";
  const controller = new AbortController();

  try {
    const challenge = await requestPowChallenge();
    elements.startStatus.textContent = "Проверяем, что это не автоматический запрос…";
    const powSolution = await solvePow(challenge, controller.signal);

    elements.startStatus.textContent = "Создаём ключи только в памяти браузера…";
    const [sessionId, identityKeyPair] = await Promise.all([
      Promise.resolve(createSessionId()),
      createIdentityKeyPair(),
    ]);
    const ready = await registerSocket({
      sessionId,
      identityKeyPair,
      powSolution,
      challenge,
    });

    state.session = {
      id: ready.sessionId,
      identityPublicKey: identityKeyPair.publicKey,
      identityPrivateKey: identityKeyPair.privateKey,
    };
    elements.profileId.textContent = state.session.id;
    elements.profileKey.textContent = state.session.identityPublicKey;
    elements.startStatus.textContent = "";
    elements.startScreen.hidden = true;
    elements.workspace.hidden = false;
    renderSessionState();
  } catch (error) {
    resetToStart(error instanceof Error ? error.message : "Не удалось создать сессию.");
  } finally {
    setStartBusy(false);
  }
}

function closeCurrentSocket({ leave = true } = {}) {
  const socket = state.socket;
  state.socket = null;
  state.pendingRegistration = null;
  if (!socket) return;

  if (leave && socket.readyState === WebSocket.OPEN) {
    try {
      socket.send(JSON.stringify({ type: "session:leave" }));
    } catch {
      // The socket is already unusable.
    }
  }
  socket.close(1000, "Client closed");
}

function clearLocalSession() {
  for (const chat of state.chats.values()) {
    chat.encryptionKey = null;
    chat.thread?.remove();
  }
  for (const entry of state.outgoing.values()) {
    if (entry.ephemeralKeyPair) entry.ephemeralKeyPair.privateKey = null;
  }
  for (const pair of state.accepting.values()) pair.privateKey = null;

  if (state.session) state.session.identityPrivateKey = null;
  state.session = null;
  state.chats.clear();
  state.incoming.clear();
  state.outgoing.clear();
  state.accepting.clear();
  state.sendingChatIds.clear();
  state.selectedChatId = null;
  state.foundUser = null;
  state.searchOperationId = null;
  state.activeRequestId = null;

  if (elements.requestDialog.open) elements.requestDialog.close();
  elements.profilePanel.hidden = true;
  elements.profileButton.setAttribute("aria-expanded", "false");
  elements.searchResult.hidden = true;
  elements.searchForm.reset();
  elements.messageInput.value = "";
  elements.messages.replaceChildren(elements.emptyChat);
  elements.emptyChat.hidden = false;
  elements.fingerprintBar.hidden = true;
  elements.workspace.classList.remove("chat-open");
  closeChatMenu();
  renderSessionState();
}

function resetToStart(statusMessage) {
  closeCurrentSocket();
  clearLocalSession();
  elements.workspace.hidden = true;
  elements.startScreen.hidden = false;
  elements.startStatus.textContent = statusMessage;
  setStartBusy(false);
}

function exitAndRotateSession() {
  if (state.starting) return;
  resetToStart("Старая сессия завершена. Создаём новую…");
  window.setTimeout(() => void createSession(), 120);
}

function renderSessionState() {
  renderIncomingRequests();
  renderOutgoingRequests();
  renderChats();
  renderSelectedChat();
}

function renderIncomingRequests() {
  elements.incomingList.replaceChildren();
  elements.incomingSection.hidden = state.incoming.size === 0;

  for (const request of state.incoming.values()) {
    const row = createElement("div", "request-item");
    const label = createElement("span", "", `Запрос от ${request.fromId}`);
    const button = createElement("button", "mini-button", "Проверить");
    button.type = "button";
    button.dataset.reviewRequest = request.requestId;
    row.append(label, button);
    elements.incomingList.append(row);
  }
}

function renderOutgoingRequests() {
  elements.outgoingList.replaceChildren();
  elements.outgoingSection.hidden = state.outgoing.size === 0;

  for (const entry of state.outgoing.values()) {
    const row = createElement("div", "request-item");
    const label = createElement(
      "span",
      "",
      entry.requestId ? `Ожидает: ${entry.targetId}` : `Отправляется: ${entry.targetId}`,
    );
    const button = createElement("button", "mini-button", "Отменить");
    button.type = "button";
    button.dataset.cancelRequest = entry.opId;
    row.append(label, button);
    elements.outgoingList.append(row);
  }
}

function renderChats() {
  elements.chatList.replaceChildren();
  elements.emptyChatList.hidden = state.chats.size > 0;

  for (const chat of state.chats.values()) {
    const button = createElement("button", "chat-item");
    button.type = "button";
    button.dataset.chatId = chat.id;
    if (chat.id === state.selectedChatId) button.classList.add("active");
    button.append(
      createElement("span", "chat-item-title", chat.peerId),
      createElement("span", "chat-item-meta", chat.fingerprint),
    );
    elements.chatList.append(button);
  }
}

function renderSelectedChat() {
  const chat = state.chats.get(state.selectedChatId) ?? null;

  for (const item of state.chats.values()) {
    item.thread.hidden = item.id !== state.selectedChatId;
  }

  const hasChat = Boolean(chat);
  elements.emptyChat.hidden = hasChat;
  elements.chatTitle.textContent = hasChat ? chat.peerId : "prrr";
  elements.chatState.textContent = hasChat ? "E2EE · AES-256-GCM" : "Ожидание собеседника";
  elements.fingerprintBar.hidden = !hasChat;
  elements.fingerprint.textContent = hasChat ? chat.fingerprint : "";
  elements.chatMenuButton.disabled = !hasChat;
  elements.messageInput.disabled = !hasChat;
  elements.workspace.classList.toggle("chat-open", hasChat);
  updateComposer();
}

function selectChat(chatId) {
  if (chatId && !state.chats.has(chatId)) return;
  state.selectedChatId = chatId;
  renderChats();
  renderSelectedChat();

  if (chatId) {
    const thread = state.chats.get(chatId)?.thread;
    if (thread) elements.messages.scrollTop = thread.scrollHeight;
  }
}

function updateComposer() {
  const chat = state.chats.get(state.selectedChatId);
  const byteLength = textEncoder.encode(elements.messageInput.value).byteLength;
  const isSending = chat ? state.sendingChatIds.has(chat.id) : false;
  const canSend = Boolean(chat)
    && byteLength > 0
    && byteLength <= MAX_MESSAGE_BYTES
    && !isSending;

  elements.byteCounter.textContent = `${byteLength} / 2 КБ`;
  elements.sendButton.disabled = !canSend;
  elements.messageInput.disabled = !chat || isSending;
}

function appendMessage(chat, direction, plaintext) {
  const wrapper = createElement("article", `message ${direction}`);
  const bubble = createElement("div", "message-bubble");
  const text = createElement("p", "message-text", plaintext);
  const time = createElement("time", "message-time", timeFormatter.format(new Date()));
  time.dateTime = new Date().toISOString();
  bubble.append(text, time);
  wrapper.append(bubble);
  chat.thread.append(wrapper);

  if (state.selectedChatId === chat.id) {
    elements.messages.scrollTop = elements.messages.scrollHeight;
  }
}

function appendSystemMessage(chat, text) {
  chat.thread.append(createElement("div", "system-message", text));
  if (state.selectedChatId === chat.id) {
    elements.messages.scrollTop = elements.messages.scrollHeight;
  }
}

function searchForUser() {
  const targetId = normalizeSessionId(elements.searchInput.value);
  elements.searchInput.value = targetId;

  if (!SESSION_ID_PATTERN.test(targetId)) {
    showToast(errorText("INVALID_SEARCH"));
    return;
  }
  if (!state.session || targetId === state.session.id) {
    showToast("Нельзя найти собственную сессию.");
    return;
  }

  state.foundUser = null;
  state.searchOperationId = createMessageId();
  elements.searchResult.hidden = true;
  elements.searchInput.disabled = true;
  elements.searchForm.querySelector("button").disabled = true;

  sendProtocol({
    type: "search",
    opId: state.searchOperationId,
    targetId,
  });
}

function finishSearchControls() {
  elements.searchInput.disabled = false;
  elements.searchForm.querySelector("button").disabled = false;
}

function handleSearchResult(message) {
  if (message.opId !== state.searchOperationId) return;
  finishSearchControls();
  state.searchOperationId = null;

  if (!message.found) {
    showToast("Пользователь не найден или уже отключился.");
    return;
  }

  state.foundUser = message.user;
  elements.searchResultId.textContent = message.user.id;
  elements.requestButton.disabled = false;
  elements.requestButton.textContent = "Отправить запрос";
  elements.searchResult.hidden = false;
}

async function sendDialogRequest() {
  const target = state.foundUser;
  if (!target || elements.requestButton.disabled) return;

  elements.requestButton.disabled = true;
  elements.requestButton.textContent = "Создаём временные ключи…";

  try {
    const ephemeralKeyPair = await createEphemeralKeyPair();
    const opId = createMessageId();
    state.outgoing.set(opId, {
      opId,
      targetId: target.id,
      identityPublicKey: target.identityPublicKey,
      ephemeralKeyPair,
      requestId: null,
    });

    const sent = sendProtocol({
      type: "dialog:request",
      opId,
      to: target.id,
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
    });
    if (!sent) {
      ephemeralKeyPair.privateKey = null;
      state.outgoing.delete(opId);
      throw new Error("Нет соединения с сервером.");
    }

    elements.requestButton.textContent = "Запрос отправляется…";
    renderOutgoingRequests();
  } catch {
    elements.requestButton.disabled = false;
    elements.requestButton.textContent = "Отправить запрос";
    showToast("Не удалось создать временные ключи.");
  }
}

function handleDialogRequestSent(message) {
  const entry = state.outgoing.get(message.opId);
  if (!entry) return;
  entry.requestId = message.requestId;
  elements.requestButton.textContent = "Запрос отправлен";
  renderOutgoingRequests();
}

function cancelOutgoingRequest(opId) {
  const entry = state.outgoing.get(opId);
  if (!entry) return;

  if (entry.requestId) {
    sendProtocol({ type: "dialog:cancel", requestId: entry.requestId });
  }
  if (entry.ephemeralKeyPair) entry.ephemeralKeyPair.privateKey = null;
  state.outgoing.delete(opId);
  renderOutgoingRequests();
  if (state.foundUser?.id === entry.targetId) {
    elements.requestButton.disabled = false;
    elements.requestButton.textContent = "Отправить запрос";
  }
}

function handleIncomingRequest(message) {
  if (
    typeof message.requestId !== "string"
    || typeof message.from?.id !== "string"
    || typeof message.from.identityPublicKey !== "string"
    || typeof message.ephemeralPublicKey !== "string"
  ) return;

  if (state.incoming.has(message.requestId)) return;
  state.incoming.set(message.requestId, {
    requestId: message.requestId,
    fromId: message.from.id,
    identityPublicKey: message.from.identityPublicKey,
    ephemeralPublicKey: message.ephemeralPublicKey,
  });
  renderIncomingRequests();
  showToast(`Входящий запрос от ${message.from.id}`);
  showNextRequestDialog();
}

function showNextRequestDialog() {
  if (state.activeRequestId || elements.requestDialog.open || state.incoming.size === 0) return;
  const [requestId, request] = state.incoming.entries().next().value;
  state.activeRequestId = requestId;
  elements.requestDialogId.textContent = request.fromId;
  elements.acceptRequestButton.disabled = false;
  elements.rejectRequestButton.disabled = false;
  elements.requestDialog.showModal();
}

function closeRequestDialog() {
  if (elements.requestDialog.open) elements.requestDialog.close();
  state.activeRequestId = null;
  queueMicrotask(showNextRequestDialog);
}

function reviewRequest(requestId) {
  if (!state.incoming.has(requestId) || elements.requestDialog.open) return;
  state.activeRequestId = requestId;
  elements.requestDialogId.textContent = state.incoming.get(requestId).fromId;
  elements.acceptRequestButton.disabled = false;
  elements.rejectRequestButton.disabled = false;
  elements.requestDialog.showModal();
}

function rejectActiveRequest() {
  const requestId = state.activeRequestId;
  if (!requestId) return;
  sendProtocol({ type: "dialog:reject", requestId });
  state.incoming.delete(requestId);
  closeRequestDialog();
  renderIncomingRequests();
}

async function acceptActiveRequest() {
  const requestId = state.activeRequestId;
  const request = state.incoming.get(requestId);
  if (!request) return;

  elements.acceptRequestButton.disabled = true;
  elements.rejectRequestButton.disabled = true;

  try {
    const ephemeralKeyPair = await createEphemeralKeyPair();
    state.accepting.set(requestId, ephemeralKeyPair);
    const sent = sendProtocol({
      type: "dialog:accept",
      requestId,
      ephemeralPublicKey: ephemeralKeyPair.publicKey,
    });
    if (!sent) {
      ephemeralKeyPair.privateKey = null;
      state.accepting.delete(requestId);
      throw new Error("Нет соединения с сервером.");
    }
    closeRequestDialog();
  } catch {
    elements.acceptRequestButton.disabled = false;
    elements.rejectRequestButton.disabled = false;
    state.accepting.delete(requestId);
    showToast("Не удалось создать временные ключи.");
  }
}

function handleDialogRejected(message) {
  let entry;
  for (const candidate of state.outgoing.values()) {
    if (candidate.requestId === message.requestId || candidate.opId === message.opId) {
      entry = candidate;
      break;
    }
  }

  if (entry) {
    if (entry.ephemeralKeyPair) entry.ephemeralKeyPair.privateKey = null;
    state.outgoing.delete(entry.opId);
    if (state.foundUser?.id === entry.targetId) {
      elements.requestButton.disabled = false;
      elements.requestButton.textContent = "Отправить запрос";
    }
  }

  if (state.incoming.delete(message.requestId)) closeRequestDialog();
  const acceptingPair = state.accepting.get(message.requestId);
  if (acceptingPair) acceptingPair.privateKey = null;
  state.accepting.delete(message.requestId);
  renderSessionState();

  const reason = message.reason === "offline"
    ? "Собеседник отключился."
    : message.reason === "expired"
      ? "Время запроса истекло."
      : "Запрос отклонён.";
  showToast(reason);
}

async function handleDialogAccepted(message) {
  let localPair;
  let localId;
  let peerId;
  let requestEntry;

  if (message.initiator === true) {
    requestEntry = state.outgoing.get(message.opId);
    localPair = requestEntry?.ephemeralKeyPair;
  } else {
    localPair = state.accepting.get(message.requestId);
  }

  if (!localPair) return;
  if (
    typeof message.chatId !== "string"
    || typeof message.peerId !== "string"
    || typeof message.peerEphemeralPublicKey !== "string"
    || typeof message.peerIdentityPublicKey !== "string"
  ) {
    localPair.privateKey = null;
    return;
  }

  localId = message.initiator === true ? state.session.id : message.peerId;
  peerId = message.initiator === true ? message.peerId : state.session.id;

  try {
    const context = await deriveChatContext({
      chatId: message.chatId,
      localId,
      peerId,
      localPrivateKey: localPair.privateKey,
      localEphemeralPublicKey: localPair.publicKey,
      peerEphemeralPublicKey: message.peerEphemeralPublicKey,
    });

    const chat = {
      id: message.chatId,
      peerId,
      peerIdentityPublicKey: message.peerIdentityPublicKey,
      fingerprint: context.fingerprint,
      encryptionKey: context.encryptionKey,
      nextSequence: 1,
      lastReceivedSequence: 0,
      thread: createElement("div", "message-thread"),
    };
    chat.thread.hidden = true;
    state.chats.set(chat.id, chat);
    elements.messages.append(chat.thread);

    if (requestEntry) {
      requestEntry.ephemeralKeyPair.privateKey = null;
      state.outgoing.delete(requestEntry.opId);
    }
    state.incoming.delete(message.requestId);
    const acceptedPair = state.accepting.get(message.requestId);
    if (acceptedPair) acceptedPair.privateKey = null;
    state.accepting.delete(message.requestId);
    closeRequestDialog();

    selectChat(chat.id);
    renderSessionState();
    showToast("Чат создан. Сверьте отпечаток по независимому каналу.");
  } catch {
    localPair.privateKey = null;
    sendProtocol({ type: "chat:crypto-error", chatId: message.chatId });
    state.accepting.delete(message.requestId);
    if (requestEntry) {
      requestEntry.ephemeralKeyPair.privateKey = null;
      state.outgoing.delete(requestEntry.opId);
    }
    showToast("Не удалось согласовать ключи чата.");
  }
}

async function handleChatMessage(message) {
  const chat = state.chats.get(message.chatId);
  if (!chat) return;
  if (message.senderId !== chat.peerId) return;
  if (!Number.isSafeInteger(message.sequence) || message.sequence <= chat.lastReceivedSequence) return;
  if (message.plaintextSize < 1 || message.plaintextSize > MAX_MESSAGE_BYTES) return;

  try {
    const plaintext = await decryptChatMessage(chat, message, message.senderId);
    if (message.sequence <= chat.lastReceivedSequence) return;
    chat.lastReceivedSequence = message.sequence;
    appendMessage(chat, "in", plaintext);
  } catch {
    showToast("Сообщение не прошло проверку подлинности.");
  }
}

function removeChat(chatId) {
  const chat = state.chats.get(chatId);
  if (!chat) return;

  chat.encryptionKey = null;
  chat.thread.remove();
  state.chats.delete(chatId);
  state.sendingChatIds.delete(chatId);

  if (state.selectedChatId === chatId) {
    state.selectedChatId = state.chats.keys().next().value ?? null;
  }
  renderSessionState();
}

function endActiveChat() {
  const chat = state.chats.get(state.selectedChatId);
  if (!chat) return;

  const chatId = chat.id;
  sendProtocol({ type: "chat:end", chatId, opId: createMessageId() });
  closeChatMenu();
  removeChat(chatId);
  showToast("Чат завершён и удалён у обеих сторон.");
}

function handleChatEnded(message) {
  const chat = state.chats.get(message.chatId);
  if (!chat) return;
  const peerId = chat.peerId;
  removeChat(message.chatId);
  showToast(
    message.reason === "offline"
      ? `${peerId} отключился. Чат удалён.`
      : `Чат с ${peerId} завершён и удалён.`,
  );
}

async function sendCurrentMessage() {
  const chat = state.chats.get(state.selectedChatId);
  const plaintext = elements.messageInput.value;
  if (!chat || state.sendingChatIds.has(chat.id)) return;

  const byteLength = textEncoder.encode(plaintext).byteLength;
  if (byteLength < 1 || byteLength > MAX_MESSAGE_BYTES) {
    showToast("Сообщение должно быть от 1 байта до 2 КБ.");
    return;
  }

  state.sendingChatIds.add(chat.id);
  updateComposer();

  try {
    const sequence = chat.nextSequence;
    const messageId = createMessageId();
    const envelope = await encryptChatMessage(chat, plaintext, sequence, messageId);
    if (!sendProtocol({ type: "chat:message", ...envelope })) return;

    chat.nextSequence += 1;
    elements.messageInput.value = "";
    appendMessage(chat, "out", plaintext);
  } catch {
    showToast("Не удалось зашифровать сообщение.");
  } finally {
    state.sendingChatIds.delete(chat.id);
    updateComposer();
  }
}

function handleServerError(message) {
  if (message.opId && message.opId === state.searchOperationId) {
    finishSearchControls();
    state.searchOperationId = null;
  }

  const outgoingEntry = message.opId ? state.outgoing.get(message.opId) : null;
  if (outgoingEntry) {
    if (outgoingEntry.ephemeralKeyPair) outgoingEntry.ephemeralKeyPair.privateKey = null;
    state.outgoing.delete(outgoingEntry.opId);
    if (state.foundUser?.id === outgoingEntry.targetId) {
      elements.requestButton.disabled = false;
      elements.requestButton.textContent = "Отправить запрос";
    }
  }

  renderSessionState();
  showToast(errorText(message.code));
}

async function routeServerMessage(message) {
  switch (message.type) {
    case "search:result":
      handleSearchResult(message);
      break;
    case "dialog:request":
      handleIncomingRequest(message);
      break;
    case "dialog:request-sent":
      handleDialogRequestSent(message);
      break;
    case "dialog:accepted":
      await handleDialogAccepted(message);
      break;
    case "dialog:rejected":
      handleDialogRejected(message);
      break;
    case "chat:message":
      await handleChatMessage(message);
      break;
    case "chat:ended":
      handleChatEnded(message);
      break;
    case "error":
      handleServerError(message);
      break;
    default:
      break;
  }
}

function closeChatMenu() {
  elements.chatMenu.hidden = true;
  elements.chatMenuButton.setAttribute("aria-expanded", "false");
}

elements.createSessionButton.addEventListener("click", () => void createSession());
elements.exitButton.addEventListener("click", exitAndRotateSession);
elements.searchForm.addEventListener("submit", (event) => {
  event.preventDefault();
  searchForUser();
});
elements.searchInput.addEventListener("input", () => {
  elements.searchInput.value = normalizeSessionId(elements.searchInput.value);
  state.foundUser = null;
  elements.searchResult.hidden = true;
  elements.requestButton.disabled = false;
  elements.requestButton.textContent = "Отправить запрос";
});
elements.requestButton.addEventListener("click", () => void sendDialogRequest());
elements.incomingList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-review-request]");
  if (button) reviewRequest(button.dataset.reviewRequest);
});
elements.outgoingList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-cancel-request]");
  if (button) cancelOutgoingRequest(button.dataset.cancelRequest);
});
elements.chatList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-chat-id]");
  if (button) selectChat(button.dataset.chatId);
});
elements.backButton.addEventListener("click", () => selectChat(null));
elements.acceptRequestButton.addEventListener("click", () => void acceptActiveRequest());
elements.rejectRequestButton.addEventListener("click", rejectActiveRequest);
elements.requestDialog.addEventListener("cancel", (event) => {
  event.preventDefault();
  closeRequestDialog();
});
elements.requestDialog.addEventListener("close", () => {
  state.activeRequestId = null;
  queueMicrotask(showNextRequestDialog);
});
elements.chatMenuButton.addEventListener("click", (event) => {
  event.stopPropagation();
  elements.chatMenu.hidden = !elements.chatMenu.hidden;
  elements.chatMenuButton.setAttribute("aria-expanded", String(!elements.chatMenu.hidden));
});
elements.endChatButton.addEventListener("click", endActiveChat);
elements.profileButton.addEventListener("click", (event) => {
  event.stopPropagation();
  elements.profilePanel.hidden = !elements.profilePanel.hidden;
  elements.profileButton.setAttribute("aria-expanded", String(!elements.profilePanel.hidden));
});
document.addEventListener("click", (event) => {
  if (!elements.profilePanel.contains(event.target)) {
    elements.profilePanel.hidden = true;
    elements.profileButton.setAttribute("aria-expanded", "false");
  }
  if (!event.target.closest(".menu-wrap")) closeChatMenu();
});
elements.messageInput.addEventListener("input", updateComposer);
elements.messageInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    elements.messageForm.requestSubmit();
  }
});
elements.messageForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void sendCurrentMessage();
});
window.addEventListener("pagehide", () => closeCurrentSocket());
window.addEventListener("pageshow", (event) => {
  if (event.persisted && state.session) {
    resetToStart("Страница была восстановлена из кэша. Создайте новую сессию.");
  }
});

renderSessionState();
