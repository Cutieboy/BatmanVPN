import Combine
import Foundation

struct StoredVPNProfile: Codable, Equatable, Identifiable {
    let id: String
    var name: String
    var endpoint: String
    var token: String
    var mouseVPNProtocol: MouseVPNProtocol

    init(
        id: String,
        name: String,
        endpoint: String,
        token: String,
        mouseVPNProtocol: MouseVPNProtocol = .legacy
    ) {
        self.id = id
        self.name = name
        self.endpoint = endpoint
        self.token = token
        self.mouseVPNProtocol = mouseVPNProtocol
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, endpoint, token
        case mouseVPNProtocol = "protocol"
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        id = try values.decode(String.self, forKey: .id)
        name = try values.decode(String.self, forKey: .name)
        endpoint = try values.decode(String.self, forKey: .endpoint)
        token = try values.decode(String.self, forKey: .token)
        mouseVPNProtocol = try values.decodeIfPresent(
            MouseVPNProtocol.self,
            forKey: .mouseVPNProtocol
        ) ?? .legacy
    }
}

@MainActor
final class ProfileStore: ObservableObject {
    @Published private(set) var profiles: [StoredVPNProfile] = []
    @Published var selectedID: String? {
        didSet {
            UserDefaults.standard.set(selectedID, forKey: Self.selectedKey)
        }
    }

    var selectedProfile: StoredVPNProfile? {
        profiles.first(where: { $0.id == selectedID }) ?? profiles.first
    }

    init() {
        selectedID = UserDefaults.standard.string(forKey: Self.selectedKey)
        load()
        if selectedProfile == nil {
            selectedID = profiles.first?.id
        }
    }

    func select(_ id: String) {
        guard profiles.contains(where: { $0.id == id }) else { return }
        selectedID = id
    }

    func save(metadata: ProfileMetadata, token: String, password: String) throws {
        let stored = StoredVPNProfile(
            id: metadata.id,
            name: metadata.name,
            endpoint: metadata.endpoint,
            token: token.trimmingCharacters(in: .whitespacesAndNewlines),
            mouseVPNProtocol: profiles.first(where: { $0.id == metadata.id })?
                .mouseVPNProtocol ?? .legacy
        )
        try ProfilePasswordKeychain.store(password, profileID: stored.id)
        if let index = profiles.firstIndex(where: { $0.id == stored.id }) {
            profiles[index] = stored
        } else {
            profiles.append(stored)
        }
        profiles.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        selectedID = stored.id
        try persist()
    }

    func password(for profile: StoredVPNProfile) throws -> String {
        try ProfilePasswordKeychain.load(profileID: profile.id)
    }

    func setProtocol(_ mouseVPNProtocol: MouseVPNProtocol, for id: String) throws {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { return }
        profiles[index].mouseVPNProtocol = mouseVPNProtocol
        try persist()
    }

    func deleteSelected() throws {
        guard let selectedID else { return }
        try ProfilePasswordKeychain.delete(profileID: selectedID)
        profiles.removeAll { $0.id == selectedID }
        self.selectedID = profiles.first?.id
        try persist()
    }

    private func load() {
        guard let url = try? storageURL(),
              let data = try? Data(contentsOf: url),
              let storage = try? JSONDecoder().decode(Storage.self, from: data),
              storage.version == 1
        else { return }
        profiles = storage.profiles
    }

    private func persist() throws {
        let url = try storageURL()
        let data = try JSONEncoder().encode(Storage(version: 1, profiles: profiles))
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func storageURL() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("MouseVPN", isDirectory: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        return support.appendingPathComponent("profiles.json")
    }

    private struct Storage: Codable {
        let version: Int
        let profiles: [StoredVPNProfile]
    }

    private static let selectedKey = "selectedProfileID"
}
