import Foundation
import Security

enum ProfilePasswordKeychain {
    private static let service = "dev.mousevpn.mac.profile-password"

    static func store(_ password: String, profileID: String) throws {
        guard let data = password.data(using: .utf8), !data.isEmpty else {
            throw KeychainError.invalidPassword
        }
        let lookup = query(profileID: profileID)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        let updateStatus = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.status(updateStatus)
        }
        var addition = lookup
        for (key, value) in attributes {
            addition[key] = value
        }
        let addStatus = SecItemAdd(addition as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError.status(addStatus)
        }
    }

    static func load(profileID: String) throws -> String {
        var lookup = query(profileID: profileID)
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &result)
        guard status != errSecItemNotFound else { throw KeychainError.notFound }
        guard status == errSecSuccess,
              let data = result as? Data,
              let password = String(data: data, encoding: .utf8)
        else { throw KeychainError.status(status) }
        return password
    }

    static func delete(profileID: String) throws {
        let status = SecItemDelete(query(profileID: profileID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.status(status)
        }
    }

    private static func query(profileID: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: profileID
        ]
    }
}

private enum KeychainError: LocalizedError {
    case invalidPassword
    case notFound
    case status(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidPassword:
            return "Пароль профиля пуст"
        case .notFound:
            return "Пароль профиля не найден в Keychain. Импортируйте профиль повторно."
        case .status(let status):
            let details = SecCopyErrorMessageString(status, nil) as String?
            return "Ошибка Keychain: \(details ?? String(status))"
        }
    }
}
