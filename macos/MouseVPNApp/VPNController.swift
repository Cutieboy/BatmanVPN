import Darwin
import Foundation

@MainActor
final class VPNController: ObservableObject {
    enum Status: String {
        case disconnected
        case connecting
        case connected
        case reconnecting
        case disconnecting
        case error
    }

    @Published private(set) var status: Status = .disconnected
    @Published private(set) var configuredServer: String?
    @Published private(set) var errorMessage: String?

    private var pollTimer: Timer?
    private var connectionAttemptActive = false
    private var disconnectRequested = false

    var isConnected: Bool { status == .connected }
    var isReconnecting: Bool { status == .reconnecting }
    var isConnecting: Bool {
        status == .connecting || status == .reconnecting || status == .disconnecting
    }

    var hasRunningHelper: Bool {
        guard let paths = try? helperPaths(),
              let pid = readHelperPID(paths.pidFile)
        else { return false }
        return processExists(pid)
    }

    var statusTitle: String {
        switch status {
        case .disconnected: return "Отключено"
        case .connecting: return "Подключение…"
        case .connected: return "Подключено"
        case .reconnecting: return "Переподключение…"
        case .disconnecting: return "Отключение…"
        case .error: return "Ошибка подключения"
        }
    }

    var menuBarSystemImage: String {
        switch status {
        case .connected: return "shield.fill"
        case .connecting, .reconnecting, .disconnecting: return "shield.lefthalf.filled"
        case .disconnected, .error: return "shield"
        }
    }

    deinit {
        pollTimer?.invalidate()
    }

    func reload() async {
        refreshFromStateFile()
        startPolling()
    }

    func inspectProfile(_ profile: VPNProfile) async throws -> ProfileMetadata {
        try profile.validate()
        let helper = try helperPaths().helper
        let input = try JSONEncoder().encode(
            HelperProfile(token: profile.token, password: profile.password)
        )
        return try await Task.detached {
            let process = Process()
            let inputPipe = Pipe()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.executableURL = helper
            process.arguments = ["--inspect-profile"]
            process.standardInput = inputPipe
            process.standardOutput = outputPipe
            process.standardError = errorPipe
            try process.run()
            inputPipe.fileHandleForWriting.write(input)
            try inputPipe.fileHandleForWriting.close()
            process.waitUntilExit()
            let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
            guard process.terminationStatus == 0 else {
                let details = String(
                    decoding: errorPipe.fileHandleForReading.readDataToEndOfFile(),
                    as: UTF8.self
                ).trimmingCharacters(in: .whitespacesAndNewlines)
                throw ControllerError.profileImportFailed(details)
            }
            return try JSONDecoder().decode(ProfileMetadata.self, from: output)
        }.value
    }

    @discardableResult
    func installAndConnect(_ profile: VPNProfile) async -> Bool {
        do {
            try profile.validate()
            connectionAttemptActive = true
            defer { connectionAttemptActive = false }
            let paths = try helperPaths()
            try FileManager.default.createDirectory(
                at: paths.supportDirectory,
                withIntermediateDirectories: true
            )
            if FileManager.default.fileExists(atPath: paths.stopFile.path) {
                try FileManager.default.removeItem(at: paths.stopFile)
            }
            let config = HelperProfile(token: profile.token, password: profile.password)
            let encoded = try JSONEncoder().encode(config)
            try encoded.write(to: paths.profile, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: paths.profile.path
            )
            try writeLocalState(
                HelperState(
                    status: Status.connecting.rawValue,
                    message: "Ожидание разрешения администратора",
                    server: nil,
                    pid: 0
                ),
                to: paths.state
            )

            status = .connecting
            configuredServer = nil
            errorMessage = nil
            let helperCommand = [
                shellQuote(paths.helper.path),
                "--config", shellQuote(paths.profile.path),
                "--state", shellQuote(paths.state.path),
                "--pid-file", shellQuote(paths.pidFile.path),
                "--stop-file", shellQuote(paths.stopFile.path),
                ">>", shellQuote(paths.log.path), "2>&1", "</dev/null", "&"
            ].joined(separator: " ")
            let command = ": > \(shellQuote(paths.log.path)); \(helperCommand)"
            try await runPrivileged(command)
            startPolling()

            for _ in 0..<120 {
                try await Task.sleep(for: .milliseconds(250))
                refreshFromStateFile()
                if status == .connected { return true }
                if status == .error || status == .disconnected { return false }
            }
            throw ControllerError.startTimedOut
        } catch {
            status = .error
            errorMessage = error.localizedDescription
            return false
        }
    }

    func disconnect() async {
        do {
            let paths = try helperPaths()
            disconnectRequested = true
            status = .disconnecting
            try Data().write(to: paths.stopFile, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: paths.stopFile.path
            )
            for _ in 0..<40 {
                try await Task.sleep(for: .milliseconds(250))
                refreshFromStateFile()
                if status == .disconnected {
                    disconnectRequested = false
                    return
                }
            }
            if let pid = readHelperPID(paths.pidFile), processExists(pid) {
                try await runPrivileged("/bin/kill -TERM \(pid)")
                for _ in 0..<20 {
                    try await Task.sleep(for: .milliseconds(250))
                    if !processExists(pid) {
                        status = .disconnected
                        configuredServer = nil
                        disconnectRequested = false
                        return
                    }
                }
                throw ControllerError.stopTimedOut
            }
            status = .disconnected
            configuredServer = nil
            disconnectRequested = false
        } catch {
            disconnectRequested = false
            status = .error
            errorMessage = error.localizedDescription
        }
    }

    func dismissError() {
        errorMessage = nil
        guard status == .error else { return }
        status = .disconnected
        if let paths = try? helperPaths() {
            try? writeLocalState(
                HelperState(
                    status: Status.disconnected.rawValue,
                    message: "VPN отключён",
                    server: configuredServer,
                    pid: 0
                ),
                to: paths.state
            )
        }
    }

    func presentError(_ error: Error) {
        status = .error
        errorMessage = error.localizedDescription
    }

    private func startPolling() {
        guard pollTimer == nil else { return }
        pollTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshFromStateFile() }
        }
    }

    private func refreshFromStateFile() {
        guard let paths = try? helperPaths(),
              let data = try? Data(contentsOf: paths.state),
              let helperState = try? JSONDecoder().decode(HelperState.self, from: data),
              let helperStatus = Status(rawValue: helperState.status)
        else { return }

        if disconnectRequested {
            if helperState.pid <= 0 || !processExists(helperState.pid) {
                status = .disconnected
                configuredServer = nil
                disconnectRequested = false
            } else {
                status = .disconnecting
            }
            return
        }

        if helperStatus == .connecting,
           helperState.pid <= 0,
           !connectionAttemptActive {
            status = .disconnected
            configuredServer = nil
            return
        }
        if [.connected, .connecting, .reconnecting].contains(helperStatus),
           helperState.pid > 0,
           !processExists(helperState.pid) {
            status = .disconnected
            return
        }
        status = helperStatus
        configuredServer = helperState.server
        if helperStatus == .error {
            errorMessage = helperState.message
        }
    }

    private func helperPaths() throws -> HelperPaths {
        let helper = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/mousevpn-macos-helper")
        guard FileManager.default.isExecutableFile(atPath: helper.path) else {
            throw ControllerError.helperMissing
        }
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("MouseVPN", isDirectory: true)
        return HelperPaths(
            helper: helper,
            supportDirectory: support,
            profile: support.appendingPathComponent("profile.json"),
            state: support.appendingPathComponent("state.json"),
            pidFile: support.appendingPathComponent("helper.pid"),
            stopFile: support.appendingPathComponent("stop-request"),
            log: support.appendingPathComponent("helper.log")
        )
    }

    private func runPrivileged(_ shellCommand: String) async throws {
        let escaped = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        try await Task.detached {
            let process = Process()
            let errorPipe = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", script]
            process.standardError = errorPipe
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                let data = errorPipe.fileHandleForReading.readDataToEndOfFile()
                let message = String(decoding: data, as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                throw ControllerError.authorizationFailed(message)
            }
        }.value
    }

    private func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func processExists(_ pid: Int32) -> Bool {
        kill(pid, 0) == 0 || errno == EPERM
    }

    private func readHelperPID(_ url: URL) -> Int32? {
        guard let contents = try? String(contentsOf: url, encoding: .utf8),
              let pid = Int32(contents.trimmingCharacters(in: .whitespacesAndNewlines)),
              pid > 1
        else { return nil }
        return pid
    }

    private func writeLocalState(_ state: HelperState, to url: URL) throws {
        try JSONEncoder().encode(state).write(to: url, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644],
            ofItemAtPath: url.path
        )
    }
}

private struct HelperProfile: Codable {
    let token: String
    let password: String
}

struct ProfileMetadata: Codable {
    let id: String
    let name: String
    let endpoint: String
}

private struct HelperState: Codable {
    let status: String
    let message: String
    let server: String?
    let pid: Int32
}

private struct HelperPaths {
    let helper: URL
    let supportDirectory: URL
    let profile: URL
    let state: URL
    let pidFile: URL
    let stopFile: URL
    let log: URL
}

private enum ControllerError: LocalizedError {
    case helperMissing
    case authorizationFailed(String)
    case profileImportFailed(String)
    case startTimedOut
    case stopTimedOut

    var errorDescription: String? {
        switch self {
        case .helperMissing:
            return "В приложении не найден фоновый MouseVPN helper. Пересоберите проект."
        case .authorizationFailed(let details):
            return details.isEmpty
                ? "macOS не дала разрешение на запуск VPN helper"
                : "Не удалось получить права администратора: \(details)"
        case .profileImportFailed(let details):
            return details.isEmpty
                ? "Не удалось расшифровать MV1-профиль"
                : details.replacingOccurrences(of: "MouseVPN helper failed: ", with: "")
        case .startTimedOut:
            return "VPN helper не успел подключиться. Подробности записаны в helper.log."
        case .stopTimedOut:
            return "Запущен старый VPN helper, который не реагирует на остановку. Перезагрузите Mac один раз, затем снова запустите MouseVPN из Xcode."
        }
    }
}
