import Darwin
import Foundation

@_silgen_name("wallpaper_zip_extract_entry")
private func ipaStreamExtractEntry(
    _ archivePath: UnsafePointer<CChar>,
    _ dataOffset: UInt64,
    _ compressedSize: UInt64,
    _ compressionMethod: UInt16,
    _ destinationPath: UnsafePointer<CChar>,
    _ expectedSize: UInt64,
    _ expectedCRC32: UInt32
) -> Int32

struct IpaPatchResult: Equatable {
    let outputIpaURL: URL
    let sampleEntitlementsURL: URL?
    let bundleIdentifier: String
    let displayName: String
    let version: String
    let entryCount: Int
    let outputBytes: Int64
}

enum IpaPatchError: LocalizedError {
    case invalidArchive(String)
    case missingInfoPlist
    case insufficientSpace
    case processingFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidArchive(let detail):
            return "File IPA không hợp lệ: \(detail)"
        case .missingInfoPlist:
            return "Không tìm thấy Payload/*.app/Info.plist trong file .ipa."
        case .insufficientSpace:
            return "Dung lượng trống trên iPhone không đủ để giải nén và đóng gói lại .ipa."
        case .processingFailed(let detail):
            return detail
        }
    }
}

/// Unpacks a decrypted `.ipa`, enables `UIFileSharingEnabled` & `LSSupportsOpeningDocumentsInPlace`
/// inside `Payload/*.app/Info.plist` (plus optional sample `get-task-allow` entitlements for signing),
/// preserves executable POSIX permissions (`0o755`), and repacks `<name>-filesharing.ipa` into `Documents/`.
enum IpaFileSharingPatcher {
    private struct ZipEntry {
        let components: [String]
        let isDirectory: Bool
        let isSymlink: Bool
        let unixMode: UInt16
        let compressionMethod: UInt16
        let crc32: UInt32
        let compressedSize: UInt64
        let uncompressedSize: UInt64
        let dataOffset: UInt64
    }

    private struct OutEntry {
        let sourceURL: URL
        let archivePath: String
        let isDirectory: Bool
        let unixMode: UInt32
        let byteCount: UInt32
        let crc32: UInt32
        let modTime: UInt16
        let modDate: UInt16
        let localOffset: UInt32
    }

    private static let localSig: UInt32 = 0x0403_4b50
    private static let centralSig: UInt32 = 0x0201_4b50
    private static let endSig: UInt32 = 0x0605_4b50
    private static let maxArchiveBytes: UInt64 = 3_900_000_000
    private static let maxEntryCount = 120_000
    private static let chunkBytes = 1_024 * 1_024

    static func patchIPA(
        at sourceURL: URL,
        includeSampleGetTaskAllow: Bool,
        progressHandler: ((String) -> Void)? = nil
    ) throws -> IpaPatchResult {
        let fm = FileManager.default
        let hasScope = sourceURL.startAccessingSecurityScopedResource()
        defer {
            if hasScope {
                sourceURL.stopAccessingSecurityScopedResource()
            }
        }

        let cleanSource = sourceURL.standardizedFileURL
        let vals = try cleanSource.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard vals.isRegularFile == true, let fSize = vals.fileSize, fSize >= 22 else {
            throw IpaPatchError.invalidArchive("Không đọc được kích thước file .ipa.")
        }
        guard UInt64(fSize) <= maxArchiveBytes else {
            throw IpaPatchError.invalidArchive("Kích thước vượt quá giới hạn ZIP 32-bit (3.9 GB).")
        }

        progressHandler?("Đang đọc cấu trúc ZIP của \(cleanSource.lastPathComponent)...")
        let handle = try FileHandle(forReadingFrom: cleanSource)
        defer { try? handle.close() }
        let entries = try parseZipEntries(handle: handle, archiveSize: UInt64(fSize))

        let totalUncompressed = entries.reduce(into: UInt64(0)) { acc, item in
            let (sum, ovf) = acc.addingReportingOverflow(item.uncompressedSize)
            acc = ovf ? UInt64.max : sum
        }
        guard totalUncompressed <= maxArchiveBytes * 2 else {
            throw IpaPatchError.invalidArchive("Tổng dung lượng giải nén vượt quá giới hạn an toàn.")
        }
        let docsRoot = try PatchWorkspaceService.documentsRootURL(fileManager: fm)
        if let avail = try docsRoot.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
            .volumeAvailableCapacityForImportantUsage, avail > 0 {
            let need = totalUncompressed.saturatingMultiplyCompat(2) + 64 * 1024 * 1024
            if need > UInt64(avail) {
                throw IpaPatchError.insufficientSpace
            }
        }

        let workDir = fm.temporaryDirectory.appendingPathComponent(".3105-ipa-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: workDir) }

        progressHandler?("Đang giải nén \(entries.count) mục trong .ipa...")
        var modeByRelativePath: [String: UInt32] = [:]

        for entry in entries {
            if entry.isSymlink {
                continue
            }
            let target = try resolveSafeURL(components: entry.components, root: workDir, isDir: entry.isDirectory)
            let relKey = entry.components.joined(separator: "/")
            if entry.unixMode != 0 {
                modeByRelativePath[relKey] = UInt32(entry.unixMode)
            }
            if entry.isDirectory {
                try fm.createDirectory(at: target, withIntermediateDirectories: true)
                continue
            }
            try fm.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
            let rc = cleanSource.path.withCString { srcPtr in
                target.path.withCString { dstPtr in
                    ipaStreamExtractEntry(
                        srcPtr,
                        entry.dataOffset,
                        entry.compressedSize,
                        entry.compressionMethod,
                        dstPtr,
                        entry.uncompressedSize,
                        entry.crc32
                    )
                }
            }
            guard rc == 0 else {
                throw IpaPatchError.processingFailed("Giải nén mục \(relKey) thất bại (mã lỗi \(rc)).")
            }
            if entry.unixMode != 0 {
                _ = chmod(target.path, mode_t(entry.unixMode & 0o7777))
            }
        }

        progressHandler?("Đang bật UIFileSharingEnabled trong Info.plist...")
        let payloadDir = workDir.appendingPathComponent("Payload", isDirectory: true)
        let payloadChildren = (try? fm.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: [.isDirectoryKey])) ?? []
        guard let appBundleDir = payloadChildren.first(where: { $0.pathExtension.lowercased() == "app" }) else {
            throw IpaPatchError.missingInfoPlist
        }
        let infoPlistURL = appBundleDir.appendingPathComponent("Info.plist")
        guard fm.fileExists(atPath: infoPlistURL.path) else {
            throw IpaPatchError.missingInfoPlist
        }

        let rawInfoData = try Data(contentsOf: infoPlistURL)
        var plistFormat: PropertyListSerialization.PropertyListFormat = .xml
        guard var plistDict = try PropertyListSerialization.propertyList(
            from: rawInfoData,
            options: .mutableContainersAndLeaves,
            format: &plistFormat
        ) as? [String: Any] else {
            throw IpaPatchError.processingFailed("Info.plist không phải dictionary hợp lệ.")
        }

        plistDict["UIFileSharingEnabled"] = true
        plistDict["LSSupportsOpeningDocumentsInPlace"] = true

        let outPlistData = try PropertyListSerialization.data(fromPropertyList: plistDict, format: plistFormat, options: 0)
        try outPlistData.write(to: infoPlistURL, options: .atomic)

        let bundleID = (plistDict["CFBundleIdentifier"] as? String) ?? "unknown.bundle"
        let displayName = (plistDict["CFBundleDisplayName"] as? String)
            ?? (plistDict["CFBundleName"] as? String)
            ?? appBundleDir.deletingPathExtension().lastPathComponent
        let version = (plistDict["CFBundleShortVersionString"] as? String)
            ?? (plistDict["CFBundleVersion"] as? String)
            ?? "1.0"
        let execName = plistDict["CFBundleExecutable"] as? String

        if let execName, !execName.isEmpty {
            let execRel = "Payload/\(appBundleDir.lastPathComponent)/\(execName)"
            modeByRelativePath[execRel] = 0o100755
            _ = chmod(appBundleDir.appendingPathComponent(execName).path, 0o755)
        }

        let baseStem = cleanSource.deletingPathExtension().lastPathComponent
        let safeStem = AirliftLanServer.sanitizedUploadFilename(baseStem)

        var sampleEntURL: URL?
        if includeSampleGetTaskAllow {
            let entitlementsDict: [String: Any] = [
                "get-task-allow": true,
                "application-identifier": "$(AppIdentifierPrefix)\(bundleID)",
                "com.apple.developer.team-identifier": "$(TeamIdentifierPrefix)"
            ]
            let entData = try PropertyListSerialization.data(fromPropertyList: entitlementsDict, format: .xml, options: 0)
            let bundleEnt = appBundleDir.appendingPathComponent("3105-Entitlements-Sample.plist")
            try entData.write(to: bundleEnt, options: .atomic)

            let docsEnt = uniqueOutputURL(stem: "\(safeStem)-filesharing-entitlements", ext: "plist", in: docsRoot)
            try entData.write(to: docsEnt, options: .atomic)
            sampleEntURL = docsEnt
        }

        progressHandler?("Đang đóng gói lại file *-filesharing.ipa vào Documents...")
        let outIpaURL = uniqueOutputURL(stem: "\(safeStem)-filesharing", ext: "ipa", in: docsRoot)
        let packedCount = try repackPayload(
            payloadDir: payloadDir,
            workRoot: workDir,
            to: outIpaURL,
            preservedModes: modeByRelativePath
        )

        let outBytes = Int64((try? outIpaURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        return IpaPatchResult(
            outputIpaURL: outIpaURL,
            sampleEntitlementsURL: sampleEntURL,
            bundleIdentifier: bundleID,
            displayName: displayName,
            version: version,
            entryCount: packedCount,
            outputBytes: outBytes
        )
    }

    // MARK: - Streaming ZIP Reader / Writer with POSIX Mode Preservation

    private static func parseZipEntries(handle: FileHandle, archiveSize: UInt64) throws -> [ZipEntry] {
        let tailSize = min(archiveSize, 65_557)
        let tailOffset = archiveSize - tailSize
        let tail = try readBytes(handle: handle, offset: tailOffset, count: Int(tailSize))
        guard let relEnd = findLastSignature(endSig, in: tail), relEnd + 22 <= tail.count else {
            throw IpaPatchError.invalidArchive("Không tìm thấy ZIP End of Central Directory.")
        }
        let endOffset = tailOffset + UInt64(relEnd)
        let entryCount = u16(tail, relEnd + 10)
        let centralSize = u32(tail, relEnd + 12)
        let centralOffset = u32(tail, relEnd + 16)
        guard entryCount != 0xffff,
              centralSize != 0xffff_ffff,
              centralOffset != 0xffff_ffff,
              Int(entryCount) <= maxEntryCount,
              UInt64(centralOffset) + UInt64(centralSize) <= endOffset else {
            throw IpaPatchError.invalidArchive("Lưu trữ ZIP64 hoặc quá lớn chưa hỗ trợ.")
        }

        var entries: [ZipEntry] = []
        var cursor = UInt64(centralOffset)
        let centralEnd = UInt64(centralOffset) + UInt64(centralSize)

        for _ in 0..<Int(entryCount) {
            let hdr = try readBytes(handle: handle, offset: cursor, count: 46)
            guard u32(hdr, 0) == centralSig else {
                throw IpaPatchError.invalidArchive("Central Directory header hỏng.")
            }
            let flags = u16(hdr, 8)
            let method = u16(hdr, 10)
            let crc = u32(hdr, 16)
            let compSize = u32(hdr, 20)
            let uncompSize = u32(hdr, 24)
            let nameLen = Int(u16(hdr, 28))
            let extraLen = Int(u16(hdr, 30))
            let commentLen = Int(u16(hdr, 32))
            let extAttr = u32(hdr, 38)
            let localOff = u32(hdr, 42)
            let varLen = nameLen + extraLen + commentLen
            guard nameLen > 0,
                  cursor + 46 + UInt64(varLen) <= centralEnd,
                  (flags & 1) == 0,
                  method == 0 || method == 8 else {
                throw IpaPatchError.invalidArchive("Mục nén không được hỗ trợ hoặc được mã hóa.")
            }

            let nameData = try readBytes(handle: handle, offset: cursor + 46, count: nameLen)
            let rawName = String(data: nameData, encoding: .utf8) ?? String(decoding: nameData, as: UTF8.self)
            let mode = UInt16((extAttr >> 16) & 0xffff)
            let fType = mode & 0o170000
            let isSym = (fType == 0o120000)
            let isDir = rawName.hasSuffix("/") || (fType == 0o040000)
            let comps = try sanitizeEntryComponents(rawName, isDir: isDir)

            let localHdr = try readBytes(handle: handle, offset: UInt64(localOff), count: 30)
            guard u32(localHdr, 0) == localSig else {
                throw IpaPatchError.invalidArchive("Local file header hỏng.")
            }
            let lNameLen = UInt64(u16(localHdr, 26))
            let lExtraLen = UInt64(u16(localHdr, 28))
            let dataOff = UInt64(localOff) + 30 + lNameLen + lExtraLen

            entries.append(ZipEntry(
                components: comps,
                isDirectory: isDir,
                isSymlink: isSym,
                unixMode: mode,
                compressionMethod: method,
                crc32: crc,
                compressedSize: UInt64(compSize),
                uncompressedSize: UInt64(uncompSize),
                dataOffset: dataOff
            ))
            cursor += 46 + UInt64(varLen)
        }
        return entries
    }

    private static func repackPayload(
        payloadDir: URL,
        workRoot: URL,
        to destinationURL: URL,
        preservedModes: [String: UInt32]
    ) throws -> Int {
        let fm = FileManager.default
        let stagingArchive = destinationURL.deletingLastPathComponent()
            .appendingPathComponent(".3105-repack-\(UUID().uuidString).ipa")
        guard fm.createFile(atPath: stagingArchive.path, contents: nil) else {
            throw IpaPatchError.processingFailed("Không thể tạo tệp IPA đầu ra.")
        }
        defer { try? fm.removeItem(at: stagingArchive) }

        let outHandle = try FileHandle(forWritingTo: stagingArchive)
        var outEntries: [OutEntry] = []

        func appendItem(url: URL, relPath: String, isDir: Bool) throws {
            let nameStr = isDir ? (relPath.hasSuffix("/") ? relPath : relPath + "/") : relPath
            guard let nameData = nameStr.data(using: .utf8) else { return }
            let vals = try? url.resourceValues(forKeys: [.fileSizeKey, .contentModificationDateKey])
            let fileSize = isDir ? 0 : Int64(vals?.fileSize ?? 0)
            let offset = try outHandle.offset()
            guard offset <= UInt64(UInt32.max), fileSize <= Int64(UInt32.max) else {
                throw IpaPatchError.invalidArchive("IPA đầu ra vượt ngưỡng 4 GB.")
            }
            let checksum = isDir ? 0 : try streamCRC32(of: url)
            let dos = dosTimeDate(vals?.contentModificationDate ?? Date())

            let mode: UInt32
            if isDir {
                mode = 0o040755
            } else if let preserved = preservedModes[relPath], preserved != 0 {
                mode = preserved
            } else if relPath.hasSuffix(".dylib") {
                mode = 0o100755
            } else {
                mode = 0o100644
            }

            let entry = OutEntry(
                sourceURL: url,
                archivePath: nameStr,
                isDirectory: isDir,
                unixMode: mode,
                byteCount: UInt32(fileSize),
                crc32: checksum,
                modTime: dos.time,
                modDate: dos.date,
                localOffset: UInt32(offset)
            )
            var hdr = Data()
            hdr.appendLE(localSig)
            hdr.appendLE(UInt16(20))
            hdr.appendLE(UInt16(1 << 11))
            hdr.appendLE(UInt16(0))
            hdr.appendLE(entry.modTime)
            hdr.appendLE(entry.modDate)
            hdr.appendLE(entry.crc32)
            hdr.appendLE(entry.byteCount)
            hdr.appendLE(entry.byteCount)
            hdr.appendLE(UInt16(nameData.count))
            hdr.appendLE(UInt16(0))
            hdr.append(nameData)
            try outHandle.write(contentsOf: hdr)

            if !isDir {
                let reader = try FileHandle(forReadingFrom: url)
                defer { try? reader.close() }
                while let chunk = try reader.read(upToCount: chunkBytes), !chunk.isEmpty {
                    try outHandle.write(contentsOf: chunk)
                }
            }
            outEntries.append(entry)
        }

        try appendItem(url: payloadDir, relPath: "Payload", isDir: true)
        if let enumerator = fm.enumerator(
            at: payloadDir,
            includingPropertiesForKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey],
            options: []
        ) {
            let rootPrefix = workRoot.standardizedFileURL.path + "/"
            while let child = enumerator.nextObject() as? URL {
                let cVals = try? child.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                if cVals?.isSymbolicLink == true { continue }
                let stdPath = child.standardizedFileURL.path
                guard stdPath.hasPrefix(rootPrefix) else { continue }
                let rel = String(stdPath.dropFirst(rootPrefix.count))
                try appendItem(url: child, relPath: rel, isDir: cVals?.isDirectory == true)
            }
        }

        let centralOffset = try outHandle.offset()
        for entry in outEntries {
            guard let nameData = entry.archivePath.data(using: .utf8) else { continue }
            var hdr = Data()
            hdr.appendLE(centralSig)
            hdr.appendLE(UInt16(0x0314))
            hdr.appendLE(UInt16(20))
            hdr.appendLE(UInt16(1 << 11))
            hdr.appendLE(UInt16(0))
            hdr.appendLE(entry.modTime)
            hdr.appendLE(entry.modDate)
            hdr.appendLE(entry.crc32)
            hdr.appendLE(entry.byteCount)
            hdr.appendLE(entry.byteCount)
            hdr.appendLE(UInt16(nameData.count))
            hdr.appendLE(UInt16(0))
            hdr.appendLE(UInt16(0))
            hdr.appendLE(UInt16(0))
            hdr.appendLE(UInt16(0))
            hdr.appendLE((entry.unixMode << 16) | (entry.isDirectory ? 0x10 : 0))
            hdr.appendLE(entry.localOffset)
            hdr.append(nameData)
            try outHandle.write(contentsOf: hdr)
        }
        let endOffset = try outHandle.offset()
        let centralSize = endOffset - centralOffset
        var endRec = Data()
        endRec.appendLE(endSig)
        endRec.appendLE(UInt16(0))
        endRec.appendLE(UInt16(0))
        endRec.appendLE(UInt16(outEntries.count))
        endRec.appendLE(UInt16(outEntries.count))
        endRec.appendLE(UInt32(centralSize))
        endRec.appendLE(UInt32(centralOffset))
        endRec.appendLE(UInt16(0))
        try outHandle.write(contentsOf: endRec)
        try outHandle.synchronize()
        try outHandle.close()

        if fm.fileExists(atPath: destinationURL.path) {
            try fm.removeItem(at: destinationURL)
        }
        try fm.moveItem(at: stagingArchive, to: destinationURL)
        return outEntries.count
    }

    private static func sanitizeEntryComponents(_ rawName: String, isDir: Bool) throws -> [String] {
        var comps = rawName.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        if isDir, comps.last == "" { comps.removeLast() }
        guard !comps.isEmpty,
              !rawName.hasPrefix("/"),
              !rawName.contains("\\"),
              comps.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw IpaPatchError.invalidArchive("Đường dẫn ZIP không hợp lệ: \(rawName)")
        }
        return comps
    }

    private static func resolveSafeURL(components: [String], root: URL, isDir: Bool) throws -> URL {
        var out = root
        for (i, c) in components.enumerated() {
            out.appendPathComponent(c, isDirectory: isDir && i == components.count - 1)
        }
        let std = out.standardizedFileURL
        guard std.path.hasPrefix(root.standardizedFileURL.path + "/") else {
            throw IpaPatchError.invalidArchive("Path traversal blocked.")
        }
        return std
    }

    private static func uniqueOutputURL(stem: String, ext: String, in folder: URL) -> URL {
        let fm = FileManager.default
        let first = folder.appendingPathComponent("\(stem).\(ext)")
        if !fm.fileExists(atPath: first.path) { return first }
        var idx = 2
        while true {
            let next = folder.appendingPathComponent("\(stem)-\(idx).\(ext)")
            if !fm.fileExists(atPath: next.path) { return next }
            idx += 1
        }
    }

    private static func readBytes(handle: FileHandle, offset: UInt64, count: Int) throws -> Data {
        try handle.seek(toOffset: offset)
        guard let d = try handle.read(upToCount: count), d.count == count else {
            throw IpaPatchError.invalidArchive("Không thể đọc dữ liệu ZIP.")
        }
        return d
    }

    private static func findLastSignature(_ sig: UInt32, in data: Data) -> Int? {
        guard data.count >= 4 else { return nil }
        for offset in stride(from: data.count - 4, through: 0, by: -1) {
            if u32(data, offset) == sig { return offset }
        }
        return nil
    }

    private static func u16(_ d: Data, _ o: Int) -> UInt16 {
        UInt16(d[o]) | (UInt16(d[o + 1]) << 8)
    }

    private static func u32(_ d: Data, _ o: Int) -> UInt32 {
        UInt32(d[o]) | (UInt32(d[o + 1]) << 8) | (UInt32(d[o + 2]) << 16) | (UInt32(d[o + 3]) << 24)
    }

    private static func streamCRC32(of url: URL) throws -> UInt32 {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var crc: UInt32 = 0xffff_ffff
        while let chunk = try handle.read(upToCount: chunkBytes), !chunk.isEmpty {
            for b in chunk {
                crc = crcTable[Int((crc ^ UInt32(b)) & 0xff)] ^ (crc >> 8)
            }
        }
        return crc ^ 0xffff_ffff
    }

    private static let crcTable: [UInt32] = (0..<256).map { value in
        var c = UInt32(value)
        for _ in 0..<8 {
            c = (c & 1) == 1 ? 0xedb8_8320 ^ (c >> 1) : c >> 1
        }
        return c
    }

    private static func dosTimeDate(_ date: Date) -> (time: UInt16, date: UInt16) {
        let cal = Calendar(identifier: .gregorian)
        let comps = cal.dateComponents(in: TimeZone.current, from: min(max(date, Date(timeIntervalSince1970: 315_532_800)), Date(timeIntervalSince1970: 4_354_819_198)))
        let year = UInt16(max(1980, min(2107, comps.year ?? 1980)) - 1980)
        let month = UInt16(max(1, min(12, comps.month ?? 1)))
        let day = UInt16(max(1, min(31, comps.day ?? 1)))
        let hour = UInt16(max(0, min(23, comps.hour ?? 0)))
        let minute = UInt16(max(0, min(59, comps.minute ?? 0)))
        let second = UInt16(max(0, min(59, comps.second ?? 0)) / 2)
        return ((hour << 11) | (minute << 5) | second, (year << 9) | (month << 5) | day)
    }
}

private extension UInt64 {
    func saturatingMultiplyCompat(_ factor: UInt64) -> UInt64 {
        let (val, ovf) = multipliedReportingOverflow(by: factor)
        return ovf ? UInt64.max : val
    }
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ val: T) {
        var le = val.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}
