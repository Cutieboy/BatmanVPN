import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var vpnController: VPNController?
    private var terminationInProgress = false

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let vpnController, vpnController.hasRunningHelper else {
            return .terminateNow
        }
        guard !terminationInProgress else {
            return .terminateLater
        }

        terminationInProgress = true
        Task { @MainActor [weak self] in
            await vpnController.disconnect()
            let disconnected = !vpnController.hasRunningHelper
            self?.terminationInProgress = false
            sender.reply(toApplicationShouldTerminate: disconnected)
            if !disconnected {
                sender.activate(ignoringOtherApps: true)
                sender.windows.first(where: { $0.canBecomeKey })?.makeKeyAndOrderFront(nil)
            }
        }
        return .terminateLater
    }
}

@main
struct MouseVPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vpn = VPNController()
    @StateObject private var profiles = ProfileStore()

    var body: some Scene {
        WindowGroup("MouseVPN", id: "main") {
            ContentView()
                .environmentObject(vpn)
                .environmentObject(profiles)
                .frame(minWidth: 540, minHeight: 520)
                .onAppear {
                    appDelegate.vpnController = vpn
                }
        }
        .windowStyle(.hiddenTitleBar)

        MenuBarExtra {
            MenuBarView()
                .environmentObject(vpn)
                .environmentObject(profiles)
                .onAppear {
                    appDelegate.vpnController = vpn
                }
        } label: {
            Label("MouseVPN — \(vpn.statusTitle)", systemImage: vpn.menuBarSystemImage)
        }
        .menuBarExtraStyle(.menu)
    }
}
