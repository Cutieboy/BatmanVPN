import AppKit
import SwiftUI

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
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
        }
        .windowStyle(.hiddenTitleBar)

        MenuBarExtra {
            MenuBarView()
                .environmentObject(vpn)
                .environmentObject(profiles)
        } label: {
            Label("MouseVPN — \(vpn.statusTitle)", systemImage: vpn.menuBarSystemImage)
        }
        .menuBarExtraStyle(.menu)
    }
}
