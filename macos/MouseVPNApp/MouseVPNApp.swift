import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var vpnController: VPNController?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let vpnController, vpnController.hasRunningHelper else {
            return .terminateNow
        }
        do {
            try vpnController.requestStopForTermination()
            return .terminateNow
        } catch {
            vpnController.presentError(error)
            sender.activate(ignoringOtherApps: true)
            sender.windows.first(where: { $0.canBecomeKey })?.makeKeyAndOrderFront(nil)
            return .terminateCancel
        }
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
