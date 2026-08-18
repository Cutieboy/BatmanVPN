import Foundation

struct VPNProfile: Equatable {
    let token: String
    let password: String

    init(token: String, password: String) {
        self.token = token.trimmingCharacters(in: .whitespacesAndNewlines)
        self.password = password
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
