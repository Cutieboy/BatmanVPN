import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var vpn: VPNController
    @EnvironmentObject private var profiles: ProfileStore
    @State private var showAddProfile = false
    @State private var confirmDelete = false
    @State private var localError: String?

    var body: some View {
        VStack(spacing: 22) {
            header
            statusCard
            profilesCard
            Spacer(minLength: 0)
        }
        .padding(28)
        .background(
            LinearGradient(
                colors: [Color(nsColor: .windowBackgroundColor), Color.cyan.opacity(0.08)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .task { await vpn.reload() }
        .sheet(isPresented: $showAddProfile) {
            AddProfileView()
                .environmentObject(vpn)
                .environmentObject(profiles)
        }
        .alert("Удалить профиль?", isPresented: $confirmDelete) {
            Button("Удалить", role: .destructive) {
                do {
                    try profiles.deleteSelected()
                } catch {
                    localError = error.localizedDescription
                }
            }
            Button("Отмена", role: .cancel) {}
        } message: {
            Text(profiles.selectedProfile?.name ?? "Выбранный профиль")
        }
        .alert("MouseVPN", isPresented: errorBinding) {
            Button("OK") {
                vpn.dismissError()
                localError = nil
            }
        } message: {
            Text(localError ?? vpn.errorMessage ?? "Неизвестная ошибка")
        }
    }

    private var header: some View {
        HStack(spacing: 14) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 34, weight: .semibold))
                .foregroundStyle(.cyan)
            VStack(alignment: .leading, spacing: 2) {
                Text("MouseVPN")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                Text("Нативный клиент для macOS")
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var statusCard: some View {
        HStack(spacing: 16) {
            Circle()
                .fill(statusColor)
                .frame(width: 12, height: 12)
                .shadow(color: statusColor.opacity(0.65), radius: vpn.isConnected ? 6 : 0)
            VStack(alignment: .leading, spacing: 3) {
                Text(vpn.statusTitle)
                    .font(.headline)
                if let server = vpn.configuredServer {
                    Text(server)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if vpn.isConnected || vpn.isConnecting {
                Button("Отключить") {
                    Task { await vpn.disconnect() }
                }
                .buttonStyle(.bordered)
            }
        }
        .padding(18)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var profilesCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text("Профили")
                    .font(.headline)
                Spacer()
                Button {
                    showAddProfile = true
                } label: {
                    Image(systemName: "plus")
                }
                .help("Добавить MV1-профиль")
                .disabled(vpn.isConnected || vpn.isConnecting)

                Button(role: .destructive) {
                    confirmDelete = true
                } label: {
                    Image(systemName: "trash")
                }
                .help("Удалить выбранный профиль")
                .disabled(
                    profiles.selectedProfile == nil || vpn.isConnected || vpn.isConnecting
                )
            }

            if profiles.profiles.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "lock.doc")
                        .font(.system(size: 30))
                        .foregroundStyle(.secondary)
                    Text("Добавьте зашифрованный профиль MV1")
                        .foregroundStyle(.secondary)
                    Button("Добавить профиль") { showAddProfile = true }
                        .buttonStyle(.borderedProminent)
                        .tint(.cyan)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 18)
            } else {
                Picker("Профиль", selection: selectedProfileBinding) {
                    ForEach(profiles.profiles) { profile in
                        Text(profile.name).tag(profile.id)
                    }
                }
                .pickerStyle(.menu)
                .disabled(vpn.isConnected || vpn.isConnecting)

                if let profile = profiles.selectedProfile {
                    HStack {
                        Image(systemName: "server.rack")
                            .foregroundStyle(.secondary)
                        Text(profile.endpoint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                        Spacer()
                    }
                }

                Button {
                    connectSelectedProfile()
                } label: {
                    HStack {
                        if vpn.isConnecting {
                            ProgressView().controlSize(.small)
                        }
                        Text(connectButtonTitle)
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .tint(.cyan)
                .controlSize(.large)
                .disabled(
                    vpn.isConnected || vpn.isConnecting
                )
            }

            Text("MV1-токены уже зашифрованы. Пароли профилей хранятся отдельно в системной Keychain.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }

    private var selectedProfileBinding: Binding<String> {
        Binding(
            get: { profiles.selectedProfile?.id ?? "" },
            set: {
                profiles.select($0)
            }
        )
    }

    private var statusColor: Color {
        if vpn.isConnected { return .green }
        if vpn.isReconnecting { return .orange }
        return .secondary.opacity(0.35)
    }

    private var connectButtonTitle: String {
        if vpn.isReconnecting { return "Переподключение…" }
        if vpn.isConnecting { return "Подключение…" }
        return "Подключить"
    }

    private var errorBinding: Binding<Bool> {
        Binding(
            get: { localError != nil || vpn.errorMessage != nil },
            set: {
                if !$0 {
                    localError = nil
                    vpn.dismissError()
                }
            }
        )
    }

    private func connectSelectedProfile() {
        guard let selected = profiles.selectedProfile else { return }
        do {
            let password = try profiles.password(for: selected)
            let profile = VPNProfile(token: selected.token, password: password)
            Task { _ = await vpn.installAndConnect(profile) }
        } catch {
            localError = error.localizedDescription
        }
    }
}

private struct AddProfileView: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var vpn: VPNController
    @EnvironmentObject private var profiles: ProfileStore
    @AppStorage("portableProfileToken") private var legacyToken = ""
    @State private var token = ""
    @State private var password = ""
    @State private var busy = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Новый профиль")
                        .font(.title2.bold())
                    Text("Импорт зашифрованного профиля MouseVPN")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Закрыть") { dismiss() }
            }

            ZStack(alignment: .topLeading) {
                if token.isEmpty {
                    Text("Вставьте MV1.…")
                        .foregroundStyle(.tertiary)
                        .padding(10)
                        .allowsHitTesting(false)
                }
                TextEditor(text: $token)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 150)
                    .scrollContentBackground(.hidden)
            }
            .padding(5)
            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.22), lineWidth: 1)
            )

            SecureField("Пароль MV1-профиля", text: $password)
                .textFieldStyle(.roundedBorder)

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            Button {
                importProfile()
            } label: {
                HStack {
                    if busy { ProgressView().controlSize(.small) }
                    Text(busy ? "Расшифровка…" : "Добавить профиль")
                        .frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(.cyan)
            .controlSize(.large)
            .disabled(busy || !token.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("MV1.") || password.utf8.count < 8)

            Text("Пароль сохранится в системной Keychain и не будет отображаться в приложении.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(24)
        .frame(width: 500, height: 430)
        .onAppear {
            if token.isEmpty { token = legacyToken }
        }
    }

    private func importProfile() {
        let candidate = VPNProfile(token: token, password: password)
        busy = true
        errorMessage = nil
        Task {
            defer { busy = false }
            do {
                let metadata = try await vpn.inspectProfile(candidate)
                try profiles.save(
                    metadata: metadata,
                    token: candidate.token,
                    password: candidate.password
                )
                password = ""
                legacyToken = ""
                dismiss()
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}
