import CommonCrypto
import CryptoKit
import Foundation
import Security

enum PatchPackageCodec {
    private static var magic: Data { GeneratedSecurityConfig.legacyMagicData() }
    static let latestSchemaVersion = 4
    private static let minimumSchemaVersion = 1

    private static let v4BundleIDToUUID: [String: UUID] = [
        "4fe0338b456ba3037ecb4cba476e27d6": UUID(uuidString: "16A78656-EE0A-41F9-B0FA-5F9F44973BBE")!,
        "48db91058470b8f242ddb2999666d8c6": UUID(uuidString: "DFC0AF84-76EF-49AF-9945-E8307FAE5C2B")!,
        "9fada8b53cd68249f2176252d3cc9de5": UUID(uuidString: "B8192D12-7013-4420-8073-794D00FB4200")!,
        "8132be7b3c12916da96e8e28a29e3cc4": UUID(uuidString: "855F300E-A213-45B6-8A14-D1EFA8D0F7AE")!,
        "4c895848faf6eb6a13ab785f91dc34d6": UUID(uuidString: "C0CA95DF-CD18-4F4A-A3CD-56DA11324716")!,
        "f9918fb30abc12499b7b06b853723995": UUID(uuidString: "5A53E415-D850-4722-ADF3-1FAE7E73F9AB")!,
        "a27ad9ec12b617ac5f6400a85438303e": UUID(uuidString: "233DAE36-3734-4E2B-8C66-C491B540B4B5")!,
        "5cb34ab1097a193bd6f0d7872f955f7d": UUID(uuidString: "F88B1A0A-E999-423E-88C3-220DF07F6F99")!,
        "a0a7f11e7561a8df259d239ae3fb8b7a": UUID(uuidString: "7EEDB6F5-3FE1-458C-B3A1-E39D72815AAA")!,
        "a520809514c122d93a77f03553d38bb9": UUID(uuidString: "4070AFA4-A4D2-4758-A7E6-6818FDCD0397")!,
        "e31c9316046d10851e5248612fba8466": UUID(uuidString: "20FF58CB-D69C-4714-AAC9-23AC249D5A30")!,
        "2dfeed2d76aa9c8006895f2eec632b00": UUID(uuidString: "7E0CDA42-4019-4958-A15C-24DCE1751464")!,
        "64894d0b2fbae6bbfd4401fd3a1e955a": UUID(uuidString: "83E9E9A7-67AC-4D87-823D-3778D897551E")!,
    ]

    static func isV4(_ data: Data) -> Bool {
        data.count >= 48 && data.prefix(4) == GeneratedSecurityConfig.v4FormatTag()
    }

    private struct Envelope: Codable {
        let schemaVersion: Int
        let keyAADVersion: Int?
        let packageID: UUID
        let isPasswordProtected: Bool
        let kdfSalt: Data?
        let kdfIterations: Int?
        let wrappedContentKey: Data?
        let publicContentKey: Data?
        let keyFingerprint: Data
        let encryptedPayload: Data
    }

    private struct Payload: Codable {
        let project: PatchProject
        let replacementDigests: [String: Data]
    }

    static func encodeNew(
        project: PatchProject,
        password: String?,
        kdfIterations: Int = PatchPackageLimits.defaultKDFIterations
    ) throws -> EncodedPatchPackage {
        try encode(
            project: project,
            password: password,
            schemaVersion: latestSchemaVersion,
            kdfIterations: kdfIterations
        )
    }

    static func encodeLegacyV1(
        project: PatchProject,
        password: String?,
        kdfIterations: Int = PatchPackageLimits.defaultKDFIterations
    ) throws -> EncodedPatchPackage {
        try encode(
            project: project,
            password: password,
            schemaVersion: 1,
            kdfIterations: kdfIterations
        )
    }

    static func encodeLegacyV2(
        project: PatchProject,
        password: String?,
        kdfIterations: Int = PatchPackageLimits.defaultKDFIterations
    ) throws -> EncodedPatchPackage {
        try encode(
            project: project,
            password: password,
            schemaVersion: 2,
            kdfIterations: kdfIterations
        )
    }

    private static func encode(
        project: PatchProject,
        password: String?,
        schemaVersion: Int,
        kdfIterations: Int
    ) throws -> EncodedPatchPackage {
        try validate(project)
        guard (minimumSchemaVersion...latestSchemaVersion).contains(schemaVersion) else {
            throw PatchPackageError.unsupportedVersion
        }
        let contentKey = try randomData(count: 32)
        let protected = !(password ?? "").isEmpty
        guard !project.isPrivate || protected else {
            throw PatchPackageError.privatePatchRequiresPassword
        }
        guard !project.isPrivate || schemaVersion >= 3 else {
            throw PatchPackageError.unsupportedVersion
        }
        let salt: Data?
        let iterations: Int?
        let wrappedKey: Data?
        let publicKey: Data?

        if protected {
            guard let password, password.utf8.count <= PatchPackageLimits.maximumPasswordBytes,
                  kdfIterations >= PatchPackageLimits.minimumKDFIterations,
                  kdfIterations <= PatchPackageLimits.maximumKDFIterations
            else {
                throw PatchPackageError.invalidProject
            }
            let generatedSalt = try randomData(count: 16)
            salt = generatedSalt
            iterations = kdfIterations
            let wrappingKey = try deriveKey(
                password: password,
                salt: generatedSalt,
                iterations: kdfIterations
            )
            wrappedKey = try seal(
                contentKey,
                key: wrappingKey,
                aad: keyAAD(for: project.id, version: schemaVersion)
            )
            publicKey = nil
        } else {
            salt = nil
            iterations = nil
            wrappedKey = nil
            publicKey = contentKey
        }

        let envelope = try makeEnvelope(
            project: project,
            schemaVersion: schemaVersion,
            keyAADVersion: protected ? schemaVersion : nil,
            contentKey: contentKey,
            isPasswordProtected: protected,
            kdfSalt: salt,
            kdfIterations: iterations,
            wrappedContentKey: wrappedKey,
            publicContentKey: publicKey
        )
        return EncodedPatchPackage(data: try serialize(envelope), contentKey: contentKey)
    }

    static func inspect(_ data: Data) throws -> PatchPackageSummary {
        if isV4(data) {
            let bidHex = data.subdata(in: 4..<20).map { String(format: "%02x", $0) }.joined()
            let mappedUUID = v4BundleIDToUUID[bidHex] ?? UUID()
            return PatchPackageSummary(
                packageID: mappedUUID,
                schemaVersion: 4,
                isPasswordProtected: true,
                keyFingerprint: Data(count: 32)
            )
        }
        let envelope = try parseEnvelope(data)
        return PatchPackageSummary(
            packageID: envelope.packageID,
            schemaVersion: envelope.schemaVersion,
            isPasswordProtected: envelope.isPasswordProtected,
            keyFingerprint: envelope.keyFingerprint
        )
    }

    /// Decrypts a sealed V4 `.3105` container purely in RAM using server-issued ephemeral bundle keys.
    static func decodeV4(_ data: Data, ticket: RuntimeSessionTicket?) throws -> DecodedPatchPackage {
        guard isV4(data) else {
            throw PatchPackageError.unsupportedFormat
        }
        let resolvedTicket = ticket ?? KeyAuthManager.shared.activeVerifiedTicket
        guard let validTicket = resolvedTicket, SecCoreBridge.shared.isActiveTicketValid(validTicket) else {
            throw PatchPackageError.privateOperationFailed
        }
        let plainBox = try SecCoreBridge.shared.decryptV4InRAM(data, ticket: validTicket)
        defer { plainBox.wipe() }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        decoder.dataDecodingStrategy = .base64
        let payload = try plainBox.withReadOnlyData { raw in
            try decoder.decode(Payload.self, from: raw)
        }

        // Enforce replacement digest integrity and strip disk persistence
        var securedProject = payload.project
        securedProject.isPrivate = true
        for rule in securedProject.rules {
            guard let expected = payload.replacementDigests[rule.id.uuidString],
                  Data(SHA256.hash(data: rule.replacementData)) == expected else {
                throw PatchPackageError.invalidPasswordOrCorruptedPackage
            }
        }
        return DecodedPatchPackage(project: securedProject, contentKey: Data())
    }

    static func decode(_ data: Data, password: String?) throws -> DecodedPatchPackage {
        if isV4(data) {
            return try decodeV4(data, ticket: nil)
        }
        do {
            let envelope = try parseEnvelope(data)
            let contentKey: Data
            if envelope.isPasswordProtected {
                guard let password,
                      !password.isEmpty,
                      password.utf8.count <= PatchPackageLimits.maximumPasswordBytes,
                      let salt = envelope.kdfSalt,
                      let iterations = envelope.kdfIterations,
                      let wrappedKey = envelope.wrappedContentKey
                else {
                    throw PatchPackageError.invalidPasswordOrCorruptedPackage
                }
                let wrappingKey = try deriveKey(password: password, salt: salt, iterations: iterations)
                contentKey = try open(
                    wrappedKey,
                    key: wrappingKey,
                    aad: keyAAD(
                        for: envelope.packageID,
                        version: envelope.keyAADVersion ?? envelope.schemaVersion
                    )
                )
            } else {
                guard let storedKey = envelope.publicContentKey else {
                    throw PatchPackageError.invalidPasswordOrCorruptedPackage
                }
                contentKey = storedKey
            }
            return try decode(envelope: envelope, contentKey: contentKey)
        } catch let error as PatchPackageError {
            switch error {
            case .unsupportedFormat, .unsupportedVersion, .sizeLimitExceeded:
                throw error
            default:
                throw PatchPackageError.invalidPasswordOrCorruptedPackage
            }
        } catch {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
    }

    static func decode(_ data: Data, contentKey: Data) throws -> DecodedPatchPackage {
        do {
            let envelope = try parseEnvelope(data)
            return try decode(envelope: envelope, contentKey: contentKey)
        } catch let error as PatchPackageError {
            switch error {
            case .unsupportedFormat, .unsupportedVersion, .sizeLimitExceeded:
                throw error
            default:
                throw PatchPackageError.invalidPasswordOrCorruptedPackage
            }
        } catch {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
    }

    static func update(
        _ originalData: Data,
        project: PatchProject,
        contentKey: Data,
        schemaVersion requestedSchemaVersion: Int? = nil
    ) throws -> Data {
        let oldEnvelope = try parseEnvelope(originalData)
        guard project.id == oldEnvelope.packageID,
              fingerprint(contentKey) == oldEnvelope.keyFingerprint
        else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        try validate(project)
        let schemaVersion = requestedSchemaVersion ?? oldEnvelope.schemaVersion
        guard (minimumSchemaVersion...latestSchemaVersion).contains(schemaVersion) else {
            throw PatchPackageError.unsupportedVersion
        }
        guard !project.isPrivate || oldEnvelope.isPasswordProtected else {
            throw PatchPackageError.privatePatchRequiresPassword
        }
        guard !project.isPrivate || schemaVersion >= 3 else {
            throw PatchPackageError.unsupportedVersion
        }
        let envelope = try makeEnvelope(
            project: project,
            schemaVersion: schemaVersion,
            keyAADVersion: oldEnvelope.isPasswordProtected
                ? (oldEnvelope.keyAADVersion ?? oldEnvelope.schemaVersion)
                : nil,
            contentKey: contentKey,
            isPasswordProtected: oldEnvelope.isPasswordProtected,
            kdfSalt: oldEnvelope.kdfSalt,
            kdfIterations: oldEnvelope.kdfIterations,
            wrappedContentKey: oldEnvelope.wrappedContentKey,
            publicContentKey: oldEnvelope.publicContentKey
        )
        return try serialize(envelope)
    }

    private static func makeEnvelope(
        project: PatchProject,
        schemaVersion: Int,
        keyAADVersion: Int?,
        contentKey: Data,
        isPasswordProtected: Bool,
        kdfSalt: Data?,
        kdfIterations: Int?,
        wrappedContentKey: Data?,
        publicContentKey: Data?
    ) throws -> Envelope {
        let digests = Dictionary(uniqueKeysWithValues: project.rules.map {
            ($0.id.uuidString, Data(SHA256.hash(data: $0.replacementData)))
        })
        let payload = Payload(project: project, replacementDigests: digests)
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let payloadData = try encoder.encode(payload)
        let encryptedPayload = try seal(
            payloadData,
            key: contentKey,
            aad: payloadAAD(for: project.id, version: schemaVersion)
        )

        return Envelope(
            schemaVersion: schemaVersion,
            keyAADVersion: keyAADVersion,
            packageID: project.id,
            isPasswordProtected: isPasswordProtected,
            kdfSalt: kdfSalt,
            kdfIterations: kdfIterations,
            wrappedContentKey: wrappedContentKey,
            publicContentKey: publicContentKey,
            keyFingerprint: fingerprint(contentKey),
            encryptedPayload: encryptedPayload
        )
    }

    private static func decode(envelope: Envelope, contentKey: Data) throws -> DecodedPatchPackage {
        guard contentKey.count == 32,
              fingerprint(contentKey) == envelope.keyFingerprint
        else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        var payloadData: Data?
        for version in [envelope.schemaVersion, 3, 2, 1] {
            if let opened = try? open(
                envelope.encryptedPayload,
                key: contentKey,
                aad: payloadAAD(for: envelope.packageID, version: version)
            ) {
                payloadData = opened
                break
            }
        }
        if payloadData == nil {
            payloadData = try? open(envelope.encryptedPayload, key: contentKey, aad: Data())
        }
        guard let decrypted = payloadData else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        let decoder = PropertyListDecoder()
        var payload: Payload
        if let p = try? decoder.decode(Payload.self, from: decrypted) {
            payload = p
        } else if let project = try? decoder.decode(PatchProject.self, from: decrypted) {
            let digests = Dictionary(project.rules.map { ($0.id.uuidString, Data(SHA256.hash(data: $0.replacementData))) }, uniquingKeysWith: { first, _ in first })
            payload = Payload(project: project, replacementDigests: digests)
        } else if let jsonProject = try? JSONDecoder().decode(PatchProject.self, from: decrypted) {
            let digests = Dictionary(jsonProject.rules.map { ($0.id.uuidString, Data(SHA256.hash(data: $0.replacementData))) }, uniquingKeysWith: { first, _ in first })
            payload = Payload(project: jsonProject, replacementDigests: digests)
        } else {
            payload = try decoder.decode(Payload.self, from: decrypted)
        }
        guard payload.project.id == envelope.packageID else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        guard !payload.project.isPrivate
                || (envelope.schemaVersion >= 3 && envelope.isPasswordProtected) else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        try validate(payload.project)
        var finalDigests = payload.replacementDigests
        if finalDigests.count != payload.project.rules.count {
            for rule in payload.project.rules {
                if finalDigests[rule.id.uuidString] == nil {
                    finalDigests[rule.id.uuidString] = Data(SHA256.hash(data: rule.replacementData))
                }
            }
        }
        guard finalDigests.count == payload.project.rules.count else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        for rule in payload.project.rules {
            let actual = Data(SHA256.hash(data: rule.replacementData))
            guard finalDigests[rule.id.uuidString] == actual else {
                throw PatchPackageError.invalidPasswordOrCorruptedPackage
            }
        }
        return DecodedPatchPackage(project: payload.project, contentKey: contentKey)
    }

    static func prepareImportData(_ data: Data) throws -> (data: Data, key: Data?) {
        if (try? inspect(data)) != nil {
            return (data, nil)
        }
        let decoder = PropertyListDecoder()
        var project: PatchProject?
        if let p = try? decoder.decode(Payload.self, from: data) {
            project = p.project
        } else if let p = try? decoder.decode(PatchProject.self, from: data) {
            project = p
        } else if let p = try? JSONDecoder().decode(PatchProject.self, from: data) {
            project = p
        }
        if let project {
            let encoded = try encodeNew(project: project, password: nil)
            return (encoded.data, encoded.contentKey)
        }
        _ = try inspect(data)
        return (data, nil)
    }

    static func validate(_ project: PatchProject) throws {
        let name = project.name.trimmingCharacters(in: .whitespacesAndNewlines)
        let author = project.author.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty,
              name.utf8.count <= 120,
              author == project.author,
              author.utf8.count <= PatchPackageLimits.maximumAuthorBytes,
              !author.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              !project.allBundleIdentifiers.isEmpty else {
            throw PatchPackageError.invalidProject
        }
        var bundles = Set<String>()
        for suppliedBundleID in project.bundleIdentifiers {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(suppliedBundleID)
            guard bundleID == suppliedBundleID,
                  bundles.insert(bundleID).inserted else {
                throw PatchPackageError.invalidProject
            }
        }
        var targets = Set<String>()
        var ruleIDs = Set<UUID>()
        var directoryIDs = Set<UUID>()
        var directoryTargets = Set<String>()
        for directory in project.directories {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(directory.bundleID)
            let relativePath = try PatchPathValidator.canonicalRelativePath(directory.relativePath)
            guard bundleID == directory.bundleID,
                  relativePath == directory.relativePath,
                  directoryIDs.insert(directory.id).inserted else {
                throw PatchPackageError.invalidProject
            }
            if !bundles.isEmpty, !bundles.contains(bundleID) {
                throw PatchPackageError.invalidProject
            }
            guard directoryTargets.insert(bundleID + "\0" + relativePath).inserted else {
                throw PatchPackageError.duplicateTarget
            }
        }
        for rule in project.rules {
            let bundleID = try PatchPathValidator.canonicalBundleIdentifier(rule.bundleID)
            let relativePath = try PatchPathValidator.canonicalRelativePath(rule.relativePath)
            guard bundleID == rule.bundleID,
                  relativePath == rule.relativePath,
                  ruleIDs.insert(rule.id).inserted,
                  !rule.replacementFilename.isEmpty,
                  rule.replacementFilename.utf8.count <= 255,
                  !rule.replacementFilename.contains("/"),
                  !rule.replacementFilename.contains("\\"),
                  !rule.replacementFilename.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
            else {
                throw PatchPackageError.invalidProject
            }
            if !bundles.isEmpty, !bundles.contains(bundleID) {
                throw PatchPackageError.invalidProject
            }
            let targetKey = bundleID + "\0" + relativePath
            guard targets.insert(targetKey).inserted,
                  !directoryTargets.contains(targetKey) else {
                throw PatchPackageError.duplicateTarget
            }
        }
    }

    private static func parseEnvelope(_ data: Data) throws -> Envelope {
        var encoded = data
        let magic10 = GeneratedSecurityConfig.legacyMagicData()
        let magic9 = magic10.prefix(9)
        if data.count > magic10.count && data.prefix(magic10.count) == magic10 {
            encoded = data.dropFirst(magic10.count)
        } else if data.count > magic9.count && data.prefix(magic9.count) == magic9 {
            encoded = data.dropFirst(magic9.count)
        }

        let envelope: Envelope
        do {
            envelope = try PropertyListDecoder().decode(Envelope.self, from: Data(encoded))
        } catch {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        guard envelope.keyFingerprint.count == 32,
              envelope.encryptedPayload.count >= 28
        else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        return envelope
    }

    private static func serialize(_ envelope: Envelope) throws -> Data {
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let body = try encoder.encode(envelope)
        var result = magic
        result.append(body)
        return result
    }

    private static func seal(_ plaintext: Data, key: Data, aad: Data) throws -> Data {
        guard key.count == 32 else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), authenticating: aad)
        guard let combined = sealed.combined else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        return combined
    }

    private static func open(_ ciphertext: Data, key: Data, aad: Data) throws -> Data {
        guard key.count == 32 else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        let box = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    private static func deriveKey(password: String, salt: Data, iterations: Int) throws -> Data {
        guard iterations >= PatchPackageLimits.minimumKDFIterations,
              iterations <= PatchPackageLimits.maximumKDFIterations else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        let passwordData = Data(password.utf8)
        let derivedKeyLength = 32
        var output = Data(count: derivedKeyLength)
        let status = output.withUnsafeMutableBytes { outputBuffer in
            passwordData.withUnsafeBytes { passwordBuffer in
                salt.withUnsafeBytes { saltBuffer in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBuffer.bindMemory(to: Int8.self).baseAddress,
                        passwordData.count,
                        saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        outputBuffer.bindMemory(to: UInt8.self).baseAddress,
                        derivedKeyLength
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            throw PatchPackageError.invalidPasswordOrCorruptedPackage
        }
        return output
    }

    private static func randomData(count: Int) throws -> Data {
        guard count > 0 else { throw PatchPackageError.invalidProject }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let baseAddress = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        guard status == errSecSuccess else {
            throw PatchPackageError.invalidProject
        }
        return data
    }

    private static func fingerprint(_ key: Data) -> Data {
        Data(SHA256.hash(data: key))
    }

    private static func keyAAD(for packageID: UUID, version: Int) -> Data {
        let pfx = String(decoding: GeneratedSecurityConfig.legacyMagicData().prefix(9), as: UTF8.self)
        return Data("\(pfx)/v\(version)/key/\(packageID.uuidString)".utf8)
    }

    private static func payloadAAD(for packageID: UUID, version: Int) -> Data {
        let pfx = String(decoding: GeneratedSecurityConfig.legacyMagicData().prefix(9), as: UTF8.self)
        return Data("\(pfx)/v\(version)/payload/\(packageID.uuidString)".utf8)
    }
}
