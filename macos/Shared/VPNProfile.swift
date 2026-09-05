import Foundation

enum MouseVPNProtocol: String, Codable, CaseIterable, Identifiable {
    case legacy
    case morphQuiet = "morph_quiet"
    case morphBalanced = "morph_balanced"
    case morphParanoid = "morph_paranoid"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .legacy: return "Legacy"
        case .morphQuiet: return "MouseMorph Quiet"
        case .morphBalanced: return "MouseMorph Balanced"
        case .morphParanoid: return "MouseMorph Paranoid"
        }
    }

    var hint: String {
        switch self {
        case .legacy: return "Совместимый режим без внешней маскировки"
        case .morphQuiet: return "Меняющийся тег и лёгкое случайное дополнение"
        case .morphBalanced: return "Пятисекундная ротация и 1–2 маскирующих пакета"
        case .morphParanoid: return "Секундная ротация и 3–5 маскирующих пакетов"
        }
    }
}

struct VPNProfile: Equatable {
    let token: String
    let password: String
    let mouseVPNProtocol: MouseVPNProtocol

    init(
        token: String,
        password: String,
        mouseVPNProtocol: MouseVPNProtocol = .legacy
    ) {
        self.token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        self.password = password
        self.mouseVPNProtocol = mouseVPNProtocol
    }

    func validate() throws {
        guard token.hasPrefix("MV1."), token.count > 4 else {
            throw ProfileError.invalidToken
        }
        guard !token.contains(where: { $0.isWhitespace }) else {
            throw ProfileError.invalidToken
        }
        guard password.utf8.count >= 8 else {
            throw ProfileError.passwordTooShort
        }
    }
}

enum ProfileError: LocalizedError {
    case invalidToken
    case passwordTooShort

    var errorDescription: String? {
        switch self {
        case .invalidToken:
            return "Вставьте полный зашифрованный профиль, начинающийся с MV1."
        case .passwordTooShort:
            return "Пароль профиля должен содержать минимум 8 символов"
        }
    }
}
