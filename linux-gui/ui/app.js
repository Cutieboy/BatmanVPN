const invoke = window.__TAURI__.core.invoke;

const elements = {
  profiles: document.querySelector("#profiles"),
  addProfile: document.querySelector("#addProfile"),
  addProfileSmall: document.querySelector("#addProfileSmall"),
  activeName: document.querySelector("#activeProfileName"),
  activeEndpoint: document.querySelector("#activeEndpoint"),
  serverValue: document.querySelector("#serverValue"),
  power: document.querySelector("#powerButton"),
  statusTitle: document.querySelector("#statusTitle"),
  statusMessage: document.querySelector("#statusMessage"),
  connectedServer: document.querySelector("#connectedServer"),
  connectedServerName: document.querySelector("#connectedServerName"),
  connectedServerEndpoint: document.querySelector("#connectedServerEndpoint"),
  badge: document.querySelector("#connectionBadge"),
  time: document.querySelector("#timeValue"),
  profileModal: document.querySelector("#profileModal"),
  profileForm: document.querySelector("#profileForm"),
  token: document.querySelector("#profileToken"),
  password: document.querySelector("#profilePassword"),
  togglePassword: document.querySelector("#togglePassword"),
  saveProfile: document.querySelector("#saveProfile"),
  formError: document.querySelector("#formError"),
  deleteModal: document.querySelector("#deleteModal"),
  deleteMessage: document.querySelector("#deleteMessage"),
  cancelDelete: document.querySelector("#cancelDelete"),
  confirmDelete: document.querySelector("#confirmDelete"),
};

let profiles = [];
let selectedId = localStorage.getItem("mousevpn.selectedProfile");
let pendingDeleteId = null;
let connection = { state: "disconnected", message: "VPN выключен", profileId: null };
let connectedAt = null;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function selectedProfile() {
  return profiles.find((profile) => profile.id === selectedId) ?? null;
}

function connectionProfile() {
  return profiles.find((profile) => profile.id === connection.profileId) ?? null;
}

function renderProfiles() {
  if (!profiles.length) {
    elements.profiles.innerHTML = '<div class="profiles-empty">Здесь появятся ваши серверы.<br>Добавьте первую конфигурацию.</div>';
  } else {
    elements.profiles.innerHTML = profiles.map((profile) => `
      <button class="profile-card ${profile.id === selectedId ? "selected" : ""}" data-profile-id="${escapeHtml(profile.id)}">
        <span class="profile-indicator"></span>
        <span class="profile-copy">
          <strong>${escapeHtml(profile.name)}</strong>
          <span>${escapeHtml(profile.endpoint)}</span>
        </span>
        <span class="delete-profile" data-delete-id="${escapeHtml(profile.id)}" role="button" aria-label="Удалить профиль">×</span>
      </button>
    `).join("");
  }
  renderActiveProfile();
}

function renderActiveProfile() {
  const profile = selectedProfile();
  const active = connectionProfile();
  elements.activeName.textContent = profile?.name ?? "Нет конфигураций";
  elements.activeEndpoint.textContent = profile?.endpoint ?? "Добавьте первый профиль";
  elements.serverValue.textContent = active
    ? `${active.name} · ${active.endpoint}`
    : (profile?.name ?? "—");
  elements.power.disabled = !profile || ["connecting", "disconnecting"].includes(connection.state);

  const showConnection = active && ["connecting", "connected", "disconnecting"].includes(connection.state);
  elements.connectedServer.classList.toggle("hidden", !showConnection);
  elements.connectedServerName.textContent = active?.name ?? "—";
  elements.connectedServerEndpoint.textContent = active?.endpoint ?? "—";
}

function renderConnection(next) {
  const previousState = connection.state;
  connection = next;
  const labels = {
    disconnected: "Отключено",
    connecting: "Подключение",
    connected: "Подключено",
    disconnecting: "Отключение",
    error: "Ошибка",
  };
  elements.badge.className = `connection-badge ${next.state}`;
  elements.badge.innerHTML = `<span></span>${labels[next.state] ?? "Неизвестно"}`;
  elements.power.classList.toggle("connected", next.state === "connected");
  elements.power.classList.toggle("busy", ["connecting", "disconnecting"].includes(next.state));
  elements.power.setAttribute("aria-label", next.state === "connected" ? "Выключить VPN" : "Включить VPN");
  elements.statusTitle.textContent = {
    disconnected: "VPN выключен",
    connecting: "Подключение…",
    connected: "VPN включён",
    disconnecting: "Отключение…",
    error: "Не удалось подключиться",
  }[next.state] ?? "MouseVPN";
  const active = connectionProfile();
  elements.statusMessage.textContent = next.state === "disconnected"
    ? (selectedProfile() ? "Нажмите, чтобы подключиться" : "Добавьте профиль, чтобы начать работу")
    : next.state === "connected" && active
      ? `Подключено к «${active.name}» — ${active.endpoint}`
      : next.message;
  if (next.state === "connected" && previousState !== "connected") connectedAt = Date.now();
  if (next.state !== "connected") {
    connectedAt = null;
    elements.time.textContent = "—";
  }
  renderActiveProfile();
}

async function refreshProfiles(preferId = null) {
  profiles = await invoke("list_profiles");
  if (preferId && profiles.some((profile) => profile.id === preferId)) selectedId = preferId;
  if (!profiles.some((profile) => profile.id === selectedId)) selectedId = profiles[0]?.id ?? null;
  if (selectedId) localStorage.setItem("mousevpn.selectedProfile", selectedId);
  else localStorage.removeItem("mousevpn.selectedProfile");
  renderProfiles();
}

function openProfileModal() {
  elements.profileModal.classList.remove("hidden");
  setTimeout(() => elements.token.focus(), 50);
}

function closeProfileModal() {
  elements.profileModal.classList.add("hidden");
  elements.profileForm.reset();
  elements.formError.classList.add("hidden");
  elements.password.type = "password";
  elements.togglePassword.textContent = "Показать";
  validateForm();
}

function validateForm() {
  elements.saveProfile.disabled = !elements.token.value.trim().startsWith("MV1.") || elements.password.value.length < 8;
}

elements.addProfile.addEventListener("click", openProfileModal);
elements.addProfileSmall.addEventListener("click", openProfileModal);
document.querySelectorAll("[data-close-modal]").forEach((button) => button.addEventListener("click", closeProfileModal));
elements.token.addEventListener("input", validateForm);
elements.password.addEventListener("input", validateForm);
elements.togglePassword.addEventListener("click", () => {
  const visible = elements.password.type === "text";
  elements.password.type = visible ? "password" : "text";
  elements.togglePassword.textContent = visible ? "Показать" : "Скрыть";
});

elements.profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.saveProfile.disabled = true;
  elements.saveProfile.textContent = "Расшифровываем…";
  elements.formError.classList.add("hidden");
  try {
    const profile = await invoke("import_profile", { token: elements.token.value.trim(), password: elements.password.value });
    closeProfileModal();
    await refreshProfiles(profile.id);
  } catch (error) {
    elements.formError.textContent = String(error);
    elements.formError.classList.remove("hidden");
  } finally {
    elements.saveProfile.textContent = "Добавить профиль";
    validateForm();
  }
});

elements.profiles.addEventListener("click", (event) => {
  const deleteControl = event.target.closest("[data-delete-id]");
  if (deleteControl) {
    event.stopPropagation();
    const profile = profiles.find((item) => item.id === deleteControl.dataset.deleteId);
    if (!profile) return;
    pendingDeleteId = profile.id;
    elements.deleteMessage.textContent = `Профиль «${profile.name}» и его ключи будут удалены с этого компьютера.`;
    elements.deleteModal.classList.remove("hidden");
    return;
  }
  const card = event.target.closest("[data-profile-id]");
  if (!card) return;
  selectedId = card.dataset.profileId;
  localStorage.setItem("mousevpn.selectedProfile", selectedId);
  renderProfiles();
});

elements.cancelDelete.addEventListener("click", () => {
  pendingDeleteId = null;
  elements.deleteModal.classList.add("hidden");
});
elements.confirmDelete.addEventListener("click", async () => {
  if (!pendingDeleteId) return;
  elements.confirmDelete.disabled = true;
  try {
    await invoke("delete_profile", { id: pendingDeleteId });
    pendingDeleteId = null;
    elements.deleteModal.classList.add("hidden");
    await refreshProfiles();
  } catch (error) {
    elements.deleteMessage.textContent = String(error);
  } finally {
    elements.confirmDelete.disabled = false;
  }
});

elements.power.addEventListener("click", async () => {
  try {
    const next = connection.state === "connected"
      ? await invoke("disconnect")
      : await invoke("connect_profile", { id: selectedId });
    renderConnection(next);
  } catch (error) {
    renderConnection({ state: "error", message: String(error), profileId: selectedId });
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (!elements.profileModal.classList.contains("hidden")) closeProfileModal();
  if (!elements.deleteModal.classList.contains("hidden")) elements.cancelDelete.click();
});

setInterval(async () => {
  try { renderConnection(await invoke("connection_status")); } catch (_) { /* retry on next tick */ }
}, 1000);

setInterval(() => {
  if (!connectedAt) return;
  const elapsed = Math.floor((Date.now() - connectedAt) / 1000);
  const hours = Math.floor(elapsed / 3600);
  const minutes = Math.floor((elapsed % 3600) / 60);
  const seconds = elapsed % 60;
  elements.time.textContent = hours > 0
    ? `${hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`
    : `${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
}, 1000);

Promise.all([refreshProfiles(), invoke("connection_status").then(renderConnection)]).catch((error) => {
  renderConnection({ state: "error", message: String(error), profileId: null });
});
