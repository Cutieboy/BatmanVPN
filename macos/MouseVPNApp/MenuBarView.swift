import AppKit
import SwiftUI

struct MenuBarView: View {
    @Environment(\.openWindow) private var openWindow
    @EnvironmentObject private var vpn: VPNController
    @EnvironmentObject private var profiles: ProfileStore

    var body: some View {
        Text(vpn.statusTitle)

        if let server = vpn.configuredServer {
            Text(server)
        }

        Divider()

        if profiles.profiles.isEmpty {
            Button("Добавить профиль…") {
                showMainWindow()
            }
        } else {
            Menu(profileMenuTitle) {
                ForEach(profiles.profiles) { profile in
                    Button {
                        profiles.select(profile.id)
                    } label: {
                        if profiles.selectedProfile?.id == profile.id {
                            Label(profile.name, systemImage: "checkmark")
                        } else {
                            Text(profile.name)
                        }
                    }
                    .disabled(vpn.isConnected || vpn.isConnecting)
                }
            }

            if vpn.isConnected || vpn.isConnecting {
                Button(vpn.isReconnecting ? "Остановить переподключение" : "Отключить") {
                    Task { await vpn.disconnect() }
                }
                .disabled(vpn.status == .disconnecting)
            } else {
                Button("Подключить") {
                    connectSelectedProfile()
                }
            }
        }

        Divider()

        Button("Открыть MouseVPN") {
            showMainWindow()
        }
        .keyboardShortcut("o")

        Button("Выйти из интерфейса") {
            NSApp.terminate(nil)
        }
        .keyboardShortcut("q")
    }

    private var profileMenuTitle: String {
        profiles.selectedProfile.map { "Профиль: \($0.name)" } ?? "Выбрать профиль"
    }

    private func connectSelectedProfile() {
        guard let selected = profiles.selectedProfile else {
            showMainWindow()
            return
        }
        do {
            let password = try profiles.password(for: selected)
            let profile = VPNProfile(token: selected.token, password: password)
            Task { _ = await vpn.installAndConnect(profile) }
        } catch {
            vpn.presentError(error)
            showMainWindow()
        }
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.async {
            NSApp.windows.first(where: { $0.canBecomeKey })?.makeKeyAndOrderFront(nil)
        }
    }
}
