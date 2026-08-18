import AppKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var vpnController: VPNController?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func applicationWillTerminate(_ notification: Notification) {
        guard vpnController?.hasRunningHelper == true else { return }
        try? vpnController?.requestStopForTermination()
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
