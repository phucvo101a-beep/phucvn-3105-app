import Combine
import Darwin
import Foundation
import Network

extension Notification.Name {
    static let airliftFilesChanged = Notification.Name("com.phucvn.3105.airliftFilesChanged")
}

struct AirliftFileItem: Codable, Identifiable {
    var id: String { relPath }
    let name: String
    let relPath: String
    let category: String
    let size: Int64
    let modifiedEpoch: TimeInterval
}

/// Lightweight Wi-Fi LAN HTTP server (`3105 Airlift`, Bonjour `_3105airlift._tcp`)
/// streaming uploads (`.ipa`, `.3105`, pairing files) and downloads directly from/to Sandbox `Documents`
/// using constant memory and `BackgroundKeepAliveManager` protection.
final class AirliftLanServer: ObservableObject {
    static let shared = AirliftLanServer()

    @Published private(set) var isRunning = false
    @Published private(set) var serverURL: String?
    @Published private(set) var port: UInt16 = 8080
    @Published private(set) var localIPAddress: String?
    @Published private(set) var lastEventMessage = "Chưa bật truyền tệp Wi-Fi LAN"
    @Published private(set) var activeTransferCount = 0
    @Published private(set) var uploadedCount = 0

    private let queue = DispatchQueue(label: "com.phucvn.3105.airlift", qos: .userInitiated)
    private var listener: NWListener?
    private var keepAliveToken: UUID?

    private init() {}

    static func airliftInboxURL(fileManager: FileManager = .default) throws -> URL {
        let docs = try PatchWorkspaceService.documentsRootURL(fileManager: fileManager)
        let dir = docs.appendingPathComponent("Airlift", isDirectory: true)
        try fileManager.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func toggle() {
        if isRunning {
            stop()
        } else {
            start()
        }
    }

    func start(preferredPort: UInt16 = 8080) {
        queue.async {
            if self.listener != nil { return }
            self.startListener(portCandidate: preferredPort, fallbackAttempts: 8)
        }
    }

    func stop() {
        queue.async {
            self.listener?.cancel()
            self.listener = nil
            if let token = self.keepAliveToken {
                BackgroundKeepAliveManager.shared.endWorkToken(token)
                self.keepAliveToken = nil
            }
            DispatchQueue.main.async {
                self.isRunning = false
                self.serverURL = nil
                self.activeTransferCount = 0
                self.lastEventMessage = "Đã tắt 3105 Airlift"
            }
        }
    }

    private func startListener(portCandidate: UInt16, fallbackAttempts: Int) {
        guard let nwPort = NWEndpoint.Port(rawValue: portCandidate) else { return }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.includePeerToPeer = true

        do {
            let newListener = try NWListener(using: params, on: nwPort)
            newListener.service = NWListener.Service(name: "3105-Airlift", type: "_3105airlift._tcp")
            newListener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    let actualPort = newListener.port?.rawValue ?? portCandidate
                    let ip = Self.detectWiFiIPv4Address() ?? "0.0.0.0"
                    let urlStr = "http://\(ip):\(actualPort)"
                    if self.keepAliveToken == nil {
                        self.keepAliveToken = BackgroundKeepAliveManager.shared.beginWorkToken()
                    }
                    log("airlift: listening at \(urlStr)")
                    DispatchQueue.main.async {
                        self.isRunning = true
                        self.port = actualPort
                        self.localIPAddress = ip
                        self.serverURL = urlStr
                        self.lastEventMessage = "Đang mở trên Wi-Fi LAN tại \(urlStr)"
                    }
                case .failed(let err):
                    log("airlift: listener failed on port \(portCandidate) — \(err.localizedDescription)")
                    newListener.cancel()
                    self.listener = nil
                    if fallbackAttempts > 0 {
                        self.startListener(portCandidate: portCandidate &+ 1, fallbackAttempts: fallbackAttempts - 1)
                    } else {
                        if let token = self.keepAliveToken {
                            BackgroundKeepAliveManager.shared.endWorkToken(token)
                            self.keepAliveToken = nil
                        }
                        DispatchQueue.main.async {
                            self.isRunning = false
                            self.serverURL = nil
                            self.lastEventMessage = "Không mở được cổng LAN: \(err.localizedDescription)"
                        }
                    }
                case .cancelled:
                    DispatchQueue.main.async {
                        self.isRunning = false
                        self.serverURL = nil
                    }
                default:
                    break
                }
            }
            newListener.newConnectionHandler = { [weak self] conn in
                self?.handleClientConnection(conn)
            }
            self.listener = newListener
            newListener.start(queue: queue)
        } catch {
            if fallbackAttempts > 0 {
                startListener(portCandidate: portCandidate &+ 1, fallbackAttempts: fallbackAttempts - 1)
            } else {
                DispatchQueue.main.async {
                    self.lastEventMessage = "Lỗi khởi tạo Airlift: \(error.localizedDescription)"
                }
            }
        }
    }

    // MARK: - HTTP Connection Streaming

    private func handleClientConnection(_ connection: NWConnection) {
        let connQueue = DispatchQueue(label: "com.phucvn.3105.airlift.conn", qos: .userInitiated)
        connection.start(queue: connQueue)
        readHTTPHeader(connection: connection, buffer: Data())
    }

    private func readHTTPHeader(connection: NWConnection, buffer: Data) {
        if buffer.count > 65_536 {
            sendTextResponse(connection: connection, status: "431 Request Header Fields Too Large", body: "Header too large")
            return
        }
        if let separatorRange = buffer.range(of: Data("\r\n\r\n".utf8)) {
            let headerData = buffer[..<separatorRange.lowerBound]
            let bodyPrefix = Data(buffer[separatorRange.upperBound...])
            guard let headerStr = String(data: headerData, encoding: .utf8) else {
                sendTextResponse(connection: connection, status: "400 Bad Request", body: "Invalid HTTP headers")
                return
            }
            dispatchParsedRequest(connection: connection, headerStr: headerStr, bodyPrefix: bodyPrefix)
            return
        }

        connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { [weak self] data, _, isComplete, error in
            guard let self else {
                connection.cancel()
                return
            }
            if let error {
                log("airlift: header read error — \(error.localizedDescription)")
                connection.cancel()
                return
            }
            if let data, !data.isEmpty {
                var next = buffer
                next.append(data)
                self.readHTTPHeader(connection: connection, buffer: next)
            } else if isComplete {
                connection.cancel()
            } else {
                self.readHTTPHeader(connection: connection, buffer: buffer)
            }
        }
    }

    private func dispatchParsedRequest(connection: NWConnection, headerStr: String, bodyPrefix: Data) {
        let lines = headerStr.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            sendTextResponse(connection: connection, status: "400 Bad Request", body: "Missing request line")
            return
        }
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count >= 2 else {
            sendTextResponse(connection: connection, status: "400 Bad Request", body: "Malformed request line")
            return
        }
        let method = parts[0].uppercased()
        let rawTarget = parts[1]

        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            if let colon = line.firstIndex(of: ":") {
                let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
                let val = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                headers[key] = val
            }
        }

        if let expect = headers["expect"], expect.lowercased().contains("100-continue") {
            let cont = Data("HTTP/1.1 100 Continue\r\n\r\n".utf8)
            connection.send(content: cont, completion: .contentProcessed({ _ in }))
        }

        let comps = URLComponents(string: "http://localhost" + rawTarget)
        let path = comps?.path ?? "/"
        let queryItems = comps?.queryItems ?? []
        let queryValue: (String) -> String? = { name in
            queryItems.first(where: { $0.name == name })?.value
        }

        switch (method, path) {
        case ("GET", "/"):
            sendDataResponse(
                connection: connection,
                status: "200 OK",
                contentType: "text/html; charset=utf-8",
                data: Data(Self.webConsoleHTML.utf8)
            )

        case ("GET", "/api/files"):
            let files = listShareableDocumentsFiles()
            let jsonData = (try? JSONEncoder().encode(["files": files])) ?? Data("{\"files\":[]}".utf8)
            sendDataResponse(
                connection: connection,
                status: "200 OK",
                contentType: "application/json; charset=utf-8",
                data: jsonData
            )

        case ("GET", "/download"):
            guard let relPath = queryValue("path"),
                  let fileURL = resolveSafeDownloadURL(relPath: relPath) else {
                sendTextResponse(connection: connection, status: "404 Not Found", body: "File not found")
                return
            }
            streamFileDownload(connection: connection, fileURL: fileURL)

        case ("POST", "/upload"), ("PUT", "/upload"):
            let contentLen = Int64(headers["content-length"] ?? "0") ?? 0
            guard contentLen > 0 else {
                sendTextResponse(connection: connection, status: "411 Length Required", body: "Content-Length required")
                return
            }
            let contentType = headers["content-type"] ?? ""
            if contentType.lowercased().contains("multipart/form-data"),
               let boundary = extractMultipartBoundary(contentType) {
                receiveMultipartUpload(
                    connection: connection,
                    contentLength: contentLen,
                    boundary: boundary,
                    initialData: bodyPrefix
                )
            } else {
                let rawName = queryValue("name") ?? headers["x-file-name"] ?? "upload-\(Int(Date().timeIntervalSince1970)).bin"
                receiveRawStreamingUpload(
                    connection: connection,
                    fileName: rawName,
                    contentLength: contentLen,
                    initialData: bodyPrefix
                )
            }

        default:
            sendTextResponse(connection: connection, status: "404 Not Found", body: "Not found")
        }
    }

    // MARK: - Streaming Uploads

    private func receiveRawStreamingUpload(
        connection: NWConnection,
        fileName: String,
        contentLength: Int64,
        initialData: Data
    ) {
        guard let tempURL = createTempUploadURL() else {
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Cannot allocate temp file")
            return
        }
        guard let fh = try? FileHandle(forWritingTo: tempURL) else {
            try? FileManager.default.removeItem(at: tempURL)
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Cannot open temp file")
            return
        }

        incrementTransfer(activeDelta: 1)
        let firstSlice = initialData.prefix(Int(min(Int64(initialData.count), contentLength)))
        if !firstSlice.isEmpty {
            try? fh.write(contentsOf: firstSlice)
        }
        let received = Int64(firstSlice.count)

        if received >= contentLength {
            try? fh.close()
            incrementTransfer(activeDelta: -1)
            finalizeUploadedFile(connection: connection, tempURL: tempURL, suggestedName: fileName, bytes: received)
            return
        }

        pumpRawUploadChunks(
            connection: connection,
            handle: fh,
            tempURL: tempURL,
            fileName: fileName,
            received: received,
            expected: contentLength
        )
    }

    private func pumpRawUploadChunks(
        connection: NWConnection,
        handle: FileHandle,
        tempURL: URL,
        fileName: String,
        received: Int64,
        expected: Int64
    ) {
        let remaining = Int(min(131_072, max(1, expected - received)))
        connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { [weak self] data, _, isComplete, error in
            guard let self else {
                try? handle.close()
                try? FileManager.default.removeItem(at: tempURL)
                connection.cancel()
                return
            }
            if let error {
                try? handle.close()
                try? FileManager.default.removeItem(at: tempURL)
                self.incrementTransfer(activeDelta: -1)
                self.sendTextResponse(connection: connection, status: "400 Bad Request", body: error.localizedDescription)
                return
            }

            var nextReceived = received
            if let data, !data.isEmpty {
                let toTake = Int(min(Int64(data.count), expected - received))
                if toTake > 0 {
                    do {
                        try handle.write(contentsOf: data.prefix(toTake))
                        nextReceived += Int64(toTake)
                    } catch {
                        try? handle.close()
                        try? FileManager.default.removeItem(at: tempURL)
                        self.incrementTransfer(activeDelta: -1)
                        self.sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Disk write failed")
                        return
                    }
                }
            }

            if nextReceived >= expected {
                try? handle.close()
                self.incrementTransfer(activeDelta: -1)
                self.finalizeUploadedFile(connection: connection, tempURL: tempURL, suggestedName: fileName, bytes: nextReceived)
            } else if isComplete {
                try? handle.close()
                try? FileManager.default.removeItem(at: tempURL)
                self.incrementTransfer(activeDelta: -1)
                self.sendTextResponse(connection: connection, status: "400 Bad Request", body: "Upload interrupted early")
            } else {
                self.pumpRawUploadChunks(
                    connection: connection,
                    handle: handle,
                    tempURL: tempURL,
                    fileName: fileName,
                    received: nextReceived,
                    expected: expected
                )
            }
        }
    }

    private func receiveMultipartUpload(
        connection: NWConnection,
        contentLength: Int64,
        boundary: String,
        initialData: Data
    ) {
        guard let tempRaw = createTempUploadURL(),
              let fh = try? FileHandle(forWritingTo: tempRaw) else {
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Temp storage error")
            return
        }
        incrementTransfer(activeDelta: 1)
        let firstSlice = initialData.prefix(Int(min(Int64(initialData.count), contentLength)))
        if !firstSlice.isEmpty {
            try? fh.write(contentsOf: firstSlice)
        }
        pumpMultipartRawBytes(
            connection: connection,
            handle: fh,
            tempURL: tempRaw,
            boundary: boundary,
            received: Int64(firstSlice.count),
            expected: contentLength
        )
    }

    private func pumpMultipartRawBytes(
        connection: NWConnection,
        handle: FileHandle,
        tempURL: URL,
        boundary: String,
        received: Int64,
        expected: Int64
    ) {
        if received >= expected {
            try? handle.close()
            incrementTransfer(activeDelta: -1)
            extractFirstMultipartPartAndFinalize(connection: connection, rawTempURL: tempURL, boundary: boundary)
            return
        }
        let remaining = Int(min(131_072, expected - received))
        connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { [weak self] data, _, isComplete, error in
            guard let self else {
                try? handle.close()
                try? FileManager.default.removeItem(at: tempURL)
                connection.cancel()
                return
            }
            if error != nil {
                try? handle.close()
                try? FileManager.default.removeItem(at: tempURL)
                self.incrementTransfer(activeDelta: -1)
                self.sendTextResponse(connection: connection, status: "400 Bad Request", body: "Upload aborted")
                return
            }
            var nextReceived = received
            if let data, !data.isEmpty {
                let toTake = Int(min(Int64(data.count), expected - received))
                if toTake > 0 {
                    try? handle.write(contentsOf: data.prefix(toTake))
                    nextReceived += Int64(toTake)
                }
            }
            if nextReceived >= expected || isComplete {
                try? handle.close()
                self.incrementTransfer(activeDelta: -1)
                if nextReceived >= expected {
                    self.extractFirstMultipartPartAndFinalize(connection: connection, rawTempURL: tempURL, boundary: boundary)
                } else {
                    try? FileManager.default.removeItem(at: tempURL)
                    self.sendTextResponse(connection: connection, status: "400 Bad Request", body: "Multipart incomplete")
                }
            } else {
                self.pumpMultipartRawBytes(
                    connection: connection,
                    handle: handle,
                    tempURL: tempURL,
                    boundary: boundary,
                    received: nextReceived,
                    expected: expected
                )
            }
        }
    }

    private func extractFirstMultipartPartAndFinalize(
        connection: NWConnection,
        rawTempURL: URL,
        boundary: String
    ) {
        defer { try? FileManager.default.removeItem(at: rawTempURL) }
        guard let reader = try? FileHandle(forReadingFrom: rawTempURL) else {
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Cannot read multipart")
            return
        }
        defer { try? reader.close() }

        let headChunk = (try? reader.read(upToCount: 8192)) ?? Data()
        let boundaryMarker = Data("--\(boundary)".utf8)
        let headerSep = Data("\r\n\r\n".utf8)
        guard let bStart = headChunk.range(of: boundaryMarker),
              let hEnd = headChunk.range(of: headerSep, range: bStart.upperBound..<headChunk.endIndex),
              let partHeaderStr = String(data: headChunk[bStart.upperBound..<hEnd.lowerBound], encoding: .utf8) else {
            sendTextResponse(connection: connection, status: "400 Bad Request", body: "Malformed multipart part")
            return
        }

        let fileName = extractMultipartFilename(partHeaderStr) ?? "upload-\(Int(Date().timeIntervalSince1970)).bin"
        let payloadStart = UInt64(hEnd.upperBound)
        let rawSize = UInt64((try? rawTempURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0)
        guard rawSize > payloadStart else {
            sendTextResponse(connection: connection, status: "400 Bad Request", body: "Empty multipart payload")
            return
        }

        // Scan tail for closing `\r\n--<boundary>`
        let tailReadStart = rawSize > 512 ? rawSize - 512 : payloadStart
        try? reader.seek(toOffset: tailReadStart)
        let tailData = (try? reader.readToEnd()) ?? Data()
        let endMarker = Data("\r\n--\(boundary)".utf8)
        let payloadEnd: UInt64
        if let endRange = tailData.range(of: endMarker) {
            payloadEnd = tailReadStart + UInt64(endRange.lowerBound)
        } else {
            payloadEnd = rawSize
        }
        guard payloadEnd >= payloadStart else {
            sendTextResponse(connection: connection, status: "400 Bad Request", body: "Invalid multipart bounds")
            return
        }

        guard let outTemp = createTempUploadURL(),
              let writer = try? FileHandle(forWritingTo: outTemp) else {
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Cannot create output")
            return
        }

        try? reader.seek(toOffset: payloadStart)
        var remaining = payloadEnd - payloadStart
        while remaining > 0 {
            let chunkLen = Int(min(131_072, remaining))
            guard let chunk = try? reader.read(upToCount: chunkLen), !chunk.isEmpty else { break }
            try? writer.write(contentsOf: chunk)
            remaining -= UInt64(chunk.count)
        }
        try? writer.close()
        finalizeUploadedFile(connection: connection, tempURL: outTemp, suggestedName: fileName, bytes: Int64(payloadEnd - payloadStart))
    }

    private func finalizeUploadedFile(
        connection: NWConnection,
        tempURL: URL,
        suggestedName: String,
        bytes: Int64
    ) {
        let fm = FileManager.default
        let safeBase = Self.sanitizedUploadFilename(suggestedName)
        let ext = (safeBase as NSString).pathExtension.lowercased()

        do {
            let destFolder: URL
            if ext == "3105" {
                destFolder = try PatchWorkspaceService.patchesRootURL(fileManager: fm)
            } else {
                destFolder = try Self.airliftInboxURL(fileManager: fm)
            }
            let destURL = uniqueDestinationURL(named: safeBase, in: destFolder, fileManager: fm)
            if fm.fileExists(atPath: destURL.path) {
                try fm.removeItem(at: destURL)
            }
            try fm.moveItem(at: tempURL, to: destURL)

            var actionNote = "Đã lưu vào \(destFolder.lastPathComponent)/\(destURL.lastPathComponent)"
            if ext == "mobiledevicepairing" || ext == "pairing"
                || ((ext == "plist" || ext == "json") && LocalDevBridge.looksLikePairingFile(at: destURL)) {
                _ = LocalDevBridge.shared.importPairingFile(from: destURL)
                actionNote = "Đã nạp tự động file Pairing: \(destURL.lastPathComponent)"
            }

            DispatchQueue.main.async {
                self.uploadedCount += 1
                self.lastEventMessage = actionNote
                NotificationCenter.default.post(name: .airliftFilesChanged, object: destURL)
            }

            let resp = [
                "ok": "true",
                "name": destURL.lastPathComponent,
                "folder": destFolder.lastPathComponent,
                "bytes": "\(bytes)",
                "message": actionNote
            ]
            let json = (try? JSONSerialization.data(withJSONObject: resp)) ?? Data("{\"ok\":true}".utf8)
            sendDataResponse(connection: connection, status: "200 OK", contentType: "application/json; charset=utf-8", data: json)
        } catch {
            try? fm.removeItem(at: tempURL)
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: error.localizedDescription)
        }
    }

    // MARK: - Streaming Downloads

    private func streamFileDownload(connection: NWConnection, fileURL: URL) {
        let size = (try? fileURL.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard let fh = try? FileHandle(forReadingFrom: fileURL) else {
            sendTextResponse(connection: connection, status: "500 Internal Server Error", body: "Cannot read file")
            return
        }
        let safeHeaderName = fileURL.lastPathComponent.replacingOccurrences(of: "\"", with: "")
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \(size)\r\nContent-Disposition: attachment; filename=\"\(safeHeaderName)\"\r\nConnection: close\r\n\r\n"
        incrementTransfer(activeDelta: 1)
        connection.send(content: Data(headers.utf8), completion: .contentProcessed({ [weak self] err in
            if err != nil {
                try? fh.close()
                self?.incrementTransfer(activeDelta: -1)
                connection.cancel()
                return
            }
            self?.pumpDownloadChunk(connection: connection, handle: fh)
        }))
    }

    private func pumpDownloadChunk(connection: NWConnection, handle: FileHandle) {
        let chunk = (try? handle.read(upToCount: 131_072)) ?? Data()
        if chunk.isEmpty {
            try? handle.close()
            incrementTransfer(activeDelta: -1)
            connection.send(content: nil, isComplete: true, completion: .contentProcessed({ _ in
                connection.cancel()
            }))
            return
        }
        connection.send(content: chunk, completion: .contentProcessed({ [weak self] err in
            if err != nil {
                try? handle.close()
                self?.incrementTransfer(activeDelta: -1)
                connection.cancel()
                return
            }
            self?.pumpDownloadChunk(connection: connection, handle: handle)
        }))
    }

    // MARK: - Sandbox Filesystem Enumeration

    func listShareableDocumentsFiles() -> [AirliftFileItem] {
        let fm = FileManager.default
        guard let docs = try? PatchWorkspaceService.documentsRootURL(fileManager: fm) else {
            return []
        }
        let canonicalDocs = docs.standardizedFileURL
        var items: [AirliftFileItem] = []

        if let enumerator = fm.enumerator(
            at: canonicalDocs,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .fileSizeKey, .contentModificationDateKey],
            options: [.skipsHiddenFiles]
        ) {
            while let fileURL = enumerator.nextObject() as? URL {
                let path = fileURL.standardizedFileURL.path
                if path.contains("/.localdev") {
                    enumerator.skipDescendants()
                    continue
                }
                guard let vals = try? fileURL.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey]),
                      vals.isRegularFile == true else {
                    continue
                }
                let prefix = canonicalDocs.path.hasSuffix("/") ? canonicalDocs.path : canonicalDocs.path + "/"
                guard path.hasPrefix(prefix) else { continue }
                let relPath = String(path.dropFirst(prefix.count))
                let firstFolder = relPath.split(separator: "/").first.map(String.init) ?? "Documents"
                items.append(AirliftFileItem(
                    name: fileURL.lastPathComponent,
                    relPath: relPath,
                    category: firstFolder,
                    size: Int64(vals.fileSize ?? 0),
                    modifiedEpoch: (vals.contentModificationDate ?? Date()).timeIntervalSince1970
                ))
            }
        }

        items.sort { $0.modifiedEpoch > $1.modifiedEpoch }
        return items
    }

    private func resolveSafeDownloadURL(relPath: String) -> URL? {
        let trimmed = relPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("/"),
              !trimmed.contains("\\"),
              !trimmed.split(separator: "/").contains(".."),
              !trimmed.contains(".localdev"),
              let docs = try? PatchWorkspaceService.documentsRootURL() else {
            return nil
        }
        let candidate = docs.appendingPathComponent(trimmed).standardizedFileURL
        let rootPath = docs.standardizedFileURL.path
        guard candidate.path.hasPrefix(rootPath + "/"),
              FileManager.default.isReadableFile(atPath: candidate.path) else {
            return nil
        }
        return candidate
    }

    // MARK: - Helpers

    private func incrementTransfer(activeDelta: Int) {
        DispatchQueue.main.async {
            self.activeTransferCount = max(0, self.activeTransferCount + activeDelta)
        }
    }

    private func createTempUploadURL() -> URL? {
        let fm = FileManager.default
        let tmpDir = fm.temporaryDirectory.appendingPathComponent("3105-Airlift-Temp", isDirectory: true)
        try? fm.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        return tmpDir.appendingPathComponent(UUID().uuidString)
    }

    private func uniqueDestinationURL(named base: String, in folder: URL, fileManager: FileManager) -> URL {
        let candidate = folder.appendingPathComponent(base)
        if !fileManager.fileExists(atPath: candidate.path) {
            return candidate
        }
        let stem = (base as NSString).deletingPathExtension
        let ext = (base as NSString).pathExtension
        var index = 2
        while true {
            let nextName = ext.isEmpty ? "\(stem) (\(index))" : "\(stem) (\(index)).\(ext)"
            let next = folder.appendingPathComponent(nextName)
            if !fileManager.fileExists(atPath: next.path) {
                return next
            }
            index += 1
        }
    }

    static func sanitizedUploadFilename(_ raw: String) -> String {
        let decoded = raw.removingPercentEncoding ?? raw
        let lastComponent = (decoded as NSString).lastPathComponent
        let clean = lastComponent
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "\\", with: "_")
            .replacingOccurrences(of: "\0", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if clean.isEmpty || clean == "." || clean == ".." {
            return "file-\(Int(Date().timeIntervalSince1970)).bin"
        }
        return clean
    }

    private func extractMultipartBoundary(_ contentType: String) -> String? {
        for part in contentType.split(separator: ";") {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.lowercased().hasPrefix("boundary=") {
                var val = String(trimmed.dropFirst("boundary=".count))
                if val.hasPrefix("\""), val.hasSuffix("\""), val.count >= 2 {
                    val = String(val.dropFirst().dropLast())
                }
                return val.isEmpty ? nil : val
            }
        }
        return nil
    }

    private func extractMultipartFilename(_ header: String) -> String? {
        for line in header.components(separatedBy: "\r\n") {
            if line.lowercased().contains("filename=") {
                if let range = line.range(of: "filename=\"") {
                    let rest = line[range.upperBound...]
                    if let quoteEnd = rest.firstIndex(of: "\"") {
                        return String(rest[..<quoteEnd])
                    }
                }
            }
        }
        return nil
    }

    private func sendTextResponse(connection: NWConnection, status: String, body: String) {
        sendDataResponse(connection: connection, status: status, contentType: "text/plain; charset=utf-8", data: Data(body.utf8))
    }

    private func sendDataResponse(connection: NWConnection, status: String, contentType: String, data: Data) {
        let header = "HTTP/1.1 \(status)\r\nContent-Type: \(contentType)\r\nContent-Length: \(data.count)\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
        var full = Data(header.utf8)
        full.append(data)
        connection.send(content: full, isComplete: true, completion: .contentProcessed({ _ in
            connection.cancel()
        }))
    }

    static func detectWiFiIPv4Address() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var preferredEn0: String?
        var fallbackIP: String?
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = cursor {
            defer { cursor = cur.pointee.ifa_next }
            let flags = Int32(cur.pointee.ifa_flags)
            guard (flags & IFF_UP) != 0, (flags & IFF_RUNNING) != 0, (flags & IFF_LOOPBACK) == 0,
                  let sa = cur.pointee.ifa_addr, sa.pointee.sa_family == sa_family_t(AF_INET) else {
                continue
            }
            let name = String(cString: cur.pointee.ifa_name)
            if name.hasPrefix("utun") || name.hasPrefix("pdp_ip") || name.hasPrefix("ipsec") {
                continue
            }
            var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NUMERICHOST) == 0 {
                let ip = String(cString: hostBuf)
                if name == "en0" {
                    preferredEn0 = ip
                    break
                } else if fallbackIP == nil {
                    fallbackIP = ip
                }
            }
        }
        return preferredEn0 ?? fallbackIP
    }

    private static let webConsoleHTML = """
    <!doctype html>
    <html lang="vi">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>3105 Airlift — Wi-Fi LAN Transfer</title>
    <style>
    body{margin:0;padding:20px;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:#0b0e14;color:#f4f7fb}
    .wrap{max-width:780px;margin:0 auto}
    .card{background:#131823;border:1px solid #242d3f;border-radius:16px;padding:18px;margin-bottom:16px}
    h1{margin:0 0 6px;font-size:22px}
    .sub{color:#8fa0b8;font-size:13px;margin:0}
    .drop{border:2px dashed #3b82f6;border-radius:14px;padding:24px;text-align:center;margin-top:14px;cursor:pointer;background:#0f172a}
    .btn{background:#3b82f6;color:#fff;border:0;border-radius:10px;padding:9px 15px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block;font-size:13px}
    .bar{height:8px;background:#1e293b;border-radius:99px;overflow:hidden;margin-top:12px;display:none}
    .fill{height:100%;width:0%;background:#22c55e;transition:width .1s}
    .row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #1f2736;gap:12px}
    .row:last-child{border-bottom:0}
    .meta{color:#8fa0b8;font-size:12px}
    </style>
    </head>
    <body>
    <div class="wrap">
      <div class="card">
        <h1>3105 x PHUCVN — Wi-Fi Airlift</h1>
        <p class="sub">Gửi nhanh .ipa, .3105, Remote Pairing (.mobiledevicepairing / .plist / .json) từ PC sang iPhone và tải tệp về PC.</p>
        <div class="drop" id="drop">
          <p style="margin:0 0 10px">Kéo thả hoặc chọn tệp để gửi sang iPhone</p>
          <input type="file" id="picker" multiple style="display:none">
          <button class="btn" onclick="document.getElementById('picker').click()">Chọn tệp từ PC</button>
          <div class="bar" id="bar"><div class="fill" id="fill"></div></div>
          <p id="status" class="meta" style="margin:10px 0 0"></p>
        </div>
      </div>
      <div class="card">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <strong>Tệp trên iPhone (Documents)</strong>
          <button class="btn" style="background:#1e293b" onclick="loadFiles()">Làm mới</button>
        </div>
        <div id="list" class="meta">Đang tải danh sách...</div>
      </div>
    </div>
    <script>
    const picker=document.getElementById('picker'),drop=document.getElementById('drop'),statusEl=document.getElementById('status'),bar=document.getElementById('bar'),fill=document.getElementById('fill');
    drop.addEventListener('dragover',e=>{e.preventDefault();drop.style.borderColor='#22c55e'});
    drop.addEventListener('dragleave',()=>{drop.style.borderColor='#3b82f6'});
    drop.addEventListener('drop',e=>{e.preventDefault();drop.style.borderColor='#3b82f6';uploadAll(e.dataTransfer.files)});
    picker.addEventListener('change',()=>uploadAll(picker.files));
    async function uploadAll(files){for(const f of files){await uploadOne(f)}loadFiles()}
    function uploadOne(file){return new Promise(res=>{bar.style.display='block';fill.style.width='0%';statusEl.textContent='Đang gửi '+file.name+'...';const x=new XMLHttpRequest();x.open('POST','/upload?name='+encodeURIComponent(file.name));x.upload.onprogress=e=>{if(e.lengthComputable){const p=Math.round(e.loaded*100/e.total);fill.style.width=p+'%';statusEl.textContent='Đang gửi '+file.name+' ('+p+'%)'}};x.onload=()=>{try{const r=JSON.parse(x.responseText);statusEl.textContent=r.message||('Xong: '+file.name)}catch(e){statusEl.textContent='Hoàn tất: '+file.name}res()};x.onerror=()=>{statusEl.textContent='Lỗi gửi '+file.name;res()};x.send(file)})}
    function fmtBytes(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(2)+' MB'}
    async function loadFiles(){const res=await fetch('/api/files');const d=await res.json();const box=document.getElementById('list');if(!d.files||!d.files.length){box.textContent='Chưa có tệp nào trong Documents.';return}box.innerHTML=d.files.map(f=>`<div class="row"><div><div style="color:#fff;font-weight:600">${f.name}</div><div class="meta">${f.relPath} · ${fmtBytes(f.size)}</div></div><a class="btn" href="/download?path=${encodeURIComponent(f.relPath)}">Tải về</a></div>`).join('')}
    loadFiles();
    </script>
    </body>
    </html>
    """
}
