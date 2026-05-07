import Foundation
import SwiftUI

enum FuzzerMode: Int, CaseIterable, Identifiable {
    case arm64Native = 0
    case arm64DryRun = 1
    case sandbox     = 2

    var id: Int { rawValue }
    var label: String {
        switch self {
        case .arm64Native: return "ARM64"
        case .arm64DryRun: return "DRY-RUN"
        case .sandbox:     return "SANDBOX"
        }
    }
    var shortName: String {
        switch self {
        case .arm64Native: return "ARM64-NATIVE"
        case .arm64DryRun: return "ARM64-DRYRUN"
        case .sandbox:     return "SANDBOX"
        }
    }
}

enum FuzzerStrategy: Int, CaseIterable, Identifiable {
    case tunnel = 0
    case brute  = 1
    case random = 2

    var id: Int { rawValue }
    var label: String {
        switch self {
        case .tunnel: return "TUNNEL"
        case .brute:  return "BRUTE"
        case .random: return "RANDOM"
        }
    }
}

struct Finding: Identifiable {
    let id = UUID()
    let signame: String
    let rawHex: String
    let siCode: Int
    let faultAddr: String
    let unknown: Bool
    let isSandbox: Bool
    let operation: String   // sandbox mode: operation name; instruction mode: ""

    var label: String {
        if isSandbox {
            return "[SANDBOX]  \(operation)  result:\(siCode)"
        }
        if signame == "CLEAN" {
            return "[CLEAN ]  \(rawHex)  (undocumented — executed cleanly)"
        }
        return "[\(signame)]  \(rawHex)  si:\(siCode)  fault:\(faultAddr)"
    }
}

@MainActor
final class FuzzerViewModel: ObservableObject {
    @Published var lines: [String] = []
    @Published var findings: [Finding] = []
    @Published var isRunning = false
    @Published var statusMessage = "Ready"
    @Published var zipURL: URL?
    @Published var droppedLineCount = 0
    @Published var selectedMode: FuzzerMode = .arm64Native
    @Published var backendMode: String = "—"
    @Published var executedCount: Int = 0
    @Published var execRate: Double = 0.0
    @Published var findingsByKind: [String: Int] = [:]
    @Published var selectedStrategy: FuzzerStrategy = .tunnel
    @Published var startHex: String = ""
    @Published var endHex: String = ""
    @Published var seedText: String = ""
    @Published var maxPacketsText: String = ""
    @Published var queueDepth: UInt32 = 0
    @Published var queueCapacity: UInt32 = 0
    @Published var skippedCount: UInt64 = 0
    @Published var lastInstruction: String = ""

    private let maxDisplayLines = 300
    private var pollTimer: Timer?
    private var logFileHandle: FileHandle?
    private var findingsFileHandle: FileHandle?
    private var logURL: URL?
    private var findingsURL: URL?
    private var startedAt: Date = Date()
    private var stoppedAt: Date = Date()
    private let pollBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: 8192)

    // Rate tracking: ring buffer of (timestamp, cumulative count) samples
    private var rateSamples: [(Date, Int)] = []
    private let rateSampleWindow: TimeInterval = 2.0

    deinit {
        pollBuf.deallocate()
    }

    // MARK: - Public interface

    func start() {
        guard !isRunning else { return }
        let seed = UInt64(seedText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        let maxPackets = UInt64(maxPacketsText.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        debugLog("start requested mode=\(selectedMode.shortName) strategy=\(selectedStrategy.label) start=\(startHex) end=\(endHex) seed=\(seed) maxPackets=\(maxPackets)")
        let result = startConfiguredScan(seed: seed, maxPackets: maxPackets)
        guard result == 0 else {
            let err = lastBackendError()
            if err.isEmpty {
                debugLog("start failed code=\(result)")
                statusMessage = "Failed to start (code \(result))"
            } else {
                debugLog("start failed code=\(result) error=\(err)")
                statusMessage = "Failed to start — see debug console"
            }
            return
        }
        openOutputFiles()
        lines = []
        findings = []
        droppedLineCount = 0
        zipURL = nil
        executedCount = 0
        execRate = 0.0
        findingsByKind = [:]
        queueDepth = 0
        queueCapacity = 0
        skippedCount = 0
        lastInstruction = ""
        rateSamples = []
        backendMode = selectedMode.shortName
        startedAt = Date()
        isRunning = true
        statusMessage = "Running..."
        debugLog("scan started mode=\(backendMode)")
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.drainQueue() }
        }
    }

    func stop() {
        pollTimer?.invalidate()
        pollTimer = nil
        sandblaster_scan_stop()
        drainQueue()
        flushAndClose()
        stoppedAt = Date()
        isRunning = false
        statusMessage = "Stopped — \(executedCount) packets, \(findings.count) findings"
        debugLog("scan stopped executed=\(executedCount) findings=\(findings.count) skipped=\(skippedCount) lastInstruction=\(lastInstruction)")
        buildZip()
    }

    private func startConfiguredScan(seed: UInt64, maxPackets: UInt64) -> Int32 {
        let start = startHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let end = endHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let mode = Int32(selectedMode.rawValue)
        let strategy = Int32(selectedStrategy.rawValue)
        let requireNative: Int32 = selectedMode == .arm64Native ? 1 : 0

        return start.withCString { startPtr in
            end.withCString { endPtr in
                sandblaster_scan_start_config(
                    mode,
                    strategy,
                    start.isEmpty ? nil : startPtr,
                    end.isEmpty ? nil : endPtr,
                    seed,
                    maxPackets,
                    5000,
                    requireNative
                )
            }
        }
    }

    // MARK: - Queue drain

    private func drainQueue() {
        var newLines: [String] = []
        while true {
            let n = sandblaster_scan_next(pollBuf, 8192)
            if n > 0 {
                if let s = String(bytes: UnsafeBufferPointer(start: pollBuf, count: Int(n)),
                                  encoding: .utf8) {
                    let t = s.trimmingCharacters(in: .newlines)
                    if !t.isEmpty { newLines.append(t) }
                }
            } else if n == 0 {
                break
            } else if n == -3 {
                pollTimer?.invalidate()
                pollTimer = nil
                flushAndClose()
                isRunning = false
                statusMessage = "Stopped — packet buffer too small"
                debugLog("scan stopped because Swift poll buffer is too small for next complete packet")
                buildZip()
                break
            } else {
                pollTimer?.invalidate()
                pollTimer = nil
                flushAndClose()
                isRunning = false
                updateBackendStatus()
                let err = lastBackendError()
                if !err.isEmpty {
                    debugLog("scan error: \(err)")
                    statusMessage = "Error — see debug console"
                } else {
                    statusMessage = "Done — \(lines.count + newLines.count) packets, \(findings.count) findings"
                    debugLog("scan done packets=\(lines.count + newLines.count) findings=\(findings.count)")
                }
                buildZip()
                break
            }
        }
        updateBackendStatus()
        guard !newLines.isEmpty else { return }

        writeLogsToFile(newLines)

        for line in newLines {
            // Detect silent dry-run fallback from Rust backend
            if line.contains("native backend unavailable") {
                backendMode = "ARM64-DRYRUN"
                debugLog(line)
            }
            if let f = parseFinding(line) {
                findings.append(f)
                writeFindingToFile(f)
                findingsByKind[f.signame, default: 0] += 1
            }
        }

        executedCount += newLines.count
        updateRate()

        lines.append(contentsOf: newLines)
        let excess = lines.count - maxDisplayLines
        if excess > 0 {
            lines.removeFirst(excess)
            droppedLineCount += excess
        }
    }

    private func updateBackendStatus() {
        var status = SandblasterScanStatus()
        guard sandblaster_scan_status(&status) == 0 else { return }
        queueDepth = status.queue_depth
        queueCapacity = status.queue_capacity
        skippedCount = status.skipped
        if let last = copyCStringLike({ buf, len in sandblaster_last_instruction(buf, len) }) {
            lastInstruction = last
        }
    }

    private func lastBackendError() -> String {
        copyCStringLike({ buf, len in sandblaster_last_error(buf, len) }) ?? ""
    }

    private func debugLog(_ message: String) {
        NSLog("[sandblaster-ios] %@", message)
    }

    private func copyCStringLike(_ call: (UnsafeMutablePointer<UInt8>?, Int32) -> Int32) -> String? {
        let cap = 4096
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: cap)
        defer { buf.deallocate() }
        let n = call(buf, Int32(cap))
        guard n > 0 else { return nil }
        return String(bytes: UnsafeBufferPointer(start: buf, count: Int(n)), encoding: .utf8)
    }

    private func updateRate() {
        let now = Date()
        rateSamples.append((now, executedCount))
        // Keep only samples within the window
        rateSamples = rateSamples.filter { now.timeIntervalSince($0.0) <= rateSampleWindow }
        guard rateSamples.count >= 2 else { execRate = 0; return }
        let oldest = rateSamples.first!
        let elapsed = now.timeIntervalSince(oldest.0)
        let delta = executedCount - oldest.1
        execRate = elapsed > 0 ? Double(delta) / elapsed : 0
    }

    // MARK: - File I/O

    private func openOutputFiles() {
        guard let dir = FileManager.default.urls(for: .documentDirectory,
                                                 in: .userDomainMask).first else { return }
        let stamp = ISO8601DateFormatter().string(from: Date())
            .replacingOccurrences(of: ":", with: "-")

        let lURL = dir.appendingPathComponent("sandblaster_logs_\(stamp).txt")
        FileManager.default.createFile(atPath: lURL.path, contents: nil)
        logFileHandle = try? FileHandle(forWritingTo: lURL)
        let logHeader = "# sandblaster ios-arm64  started: \(Date())\n"
        logFileHandle?.write(logHeader.data(using: .utf8)!)
        logURL = lURL

        let fURL = dir.appendingPathComponent("sandblaster_findings_\(stamp).txt")
        FileManager.default.createFile(atPath: fURL.path, contents: nil)
        findingsFileHandle = try? FileHandle(forWritingTo: fURL)
        let findHeader = "# sandblaster ios-arm64 findings  started: \(Date())\n"
        findingsFileHandle?.write(findHeader.data(using: .utf8)!)
        findingsURL = fURL
    }

    private func writeLogsToFile(_ batch: [String]) {
        guard let fh = logFileHandle else { return }
        let data = (batch.joined(separator: "\n") + "\n").data(using: .utf8) ?? Data()
        fh.write(data)
    }

    private func writeFindingToFile(_ f: Finding) {
        guard let fh = findingsFileHandle else { return }
        let line = f.label + "\n"
        fh.write(line.data(using: .utf8)!)
    }

    private func flushAndClose() {
        logFileHandle?.synchronizeFile()
        try? logFileHandle?.close()
        logFileHandle = nil

        findingsFileHandle?.synchronizeFile()
        try? findingsFileHandle?.close()
        findingsFileHandle = nil
    }

    // MARK: - ZIP export

    private func buildZip() {
        guard let lURL = logURL, let fURL = findingsURL else { return }
        guard let dir = FileManager.default.urls(for: .documentDirectory,
                                                 in: .userDomainMask).first else { return }
        let stamp = lURL.deletingPathExtension().lastPathComponent
            .replacingOccurrences(of: "sandblaster_logs_", with: "")
        let zURL = dir.appendingPathComponent("sandblaster_\(stamp).zip")

        var findingsData = (try? Data(contentsOf: fURL)) ?? Data()
        let footer = "# Total findings: \(findings.count)\n"
        findingsData += footer.data(using: .utf8)!

        let metaData = buildMetadata()

        do {
            let logsData = try Data(contentsOf: lURL)
            let zipData = makeZip(entries: [
                ("logs.txt", logsData),
                ("findings.txt", findingsData),
                ("metadata.json", metaData)
            ])
            try zipData.write(to: zURL)
            zipURL = zURL
        } catch {
            zipURL = lURL
        }
    }

    private func buildMetadata() -> Data {
        let iso = ISO8601DateFormatter()
        let duration = stoppedAt.timeIntervalSince(startedAt)
        let device = UIDevice.current
        var info: [String: Any] = [
            "tool": "sandblaster",
            "platform": "ios-arm64",
            "mode": selectedMode.shortName.lowercased().replacingOccurrences(of: "-", with: "_"),
            "device_model": device.model,
            "os_version": device.systemVersion,
            "started_at": iso.string(from: startedAt),
            "stopped_at": iso.string(from: stoppedAt),
            "duration_seconds": Int(duration),
            "executed_count": executedCount,
            "skipped_count": skippedCount,
            "last_instruction": lastInstruction,
            "start_hex": startHex,
            "end_hex": endHex,
            "strategy": selectedStrategy.label.lowercased(),
            "native_required": selectedMode == .arm64Native,
            "findings_count": findings.count,
            "findings_by_signal": findingsByKind
        ]
        _ = info  // suppress unused warning path
        let data = (try? JSONSerialization.data(withJSONObject: info, options: [.prettyPrinted, .sortedKeys])) ?? Data()
        return data
    }

    private func makeZip(entries: [(String, Data)]) -> Data {
        var localParts = Data()
        var centralDir = Data()

        for (name, content) in entries {
            let nameData = name.data(using: .utf8)!
            let crc = crc32OfData(content)
            let localOffset = UInt32(localParts.count)

            localParts += le32(0x04034b50)
            localParts += le16(20)
            localParts += le16(0)
            localParts += le16(0)               // store (no compression)
            localParts += le16(0)               // mod time
            localParts += le16(0x5400)          // mod date
            localParts += le32(crc)
            localParts += le32(UInt32(content.count))
            localParts += le32(UInt32(content.count))
            localParts += le16(UInt16(nameData.count))
            localParts += le16(0)               // extra field length
            localParts += nameData
            localParts += content

            centralDir += le32(0x02014b50)
            centralDir += le16(20)              // version made by
            centralDir += le16(20)              // version needed
            centralDir += le16(0)               // flags
            centralDir += le16(0)               // store
            centralDir += le16(0)               // mod time
            centralDir += le16(0x5400)          // mod date
            centralDir += le32(crc)
            centralDir += le32(UInt32(content.count))
            centralDir += le32(UInt32(content.count))
            centralDir += le16(UInt16(nameData.count))
            centralDir += le16(0)               // extra field
            centralDir += le16(0)               // comment
            centralDir += le16(0)               // disk start
            centralDir += le16(0)               // internal attrs
            centralDir += le32(0)               // external attrs
            centralDir += le32(localOffset)
            centralDir += nameData
        }

        var eocd = Data()
        eocd += le32(0x06054b50)
        eocd += le16(0)
        eocd += le16(0)
        eocd += le16(UInt16(entries.count))
        eocd += le16(UInt16(entries.count))
        eocd += le32(UInt32(centralDir.count))
        eocd += le32(UInt32(localParts.count))
        eocd += le16(0)

        return localParts + centralDir + eocd
    }

    private func crc32OfData(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data {
            let i = Int((crc ^ UInt32(byte)) & 0xFF)
            crc = (crc >> 8) ^ crc32Table[i]
        }
        return crc ^ 0xFFFFFFFF
    }

    private let crc32Table: [UInt32] = (0..<256).map { n -> UInt32 in
        var c = UInt32(n)
        for _ in 0..<8 { c = c & 1 == 0 ? c >> 1 : 0xEDB88320 ^ (c >> 1) }
        return c
    }

    private func le16(_ v: UInt16) -> Data { Data([UInt8(v & 0xFF), UInt8(v >> 8)]) }
    private func le32(_ v: UInt32) -> Data {
        Data([UInt8(v & 0xFF), UInt8((v >> 8) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8(v >> 24)])
    }

    // MARK: - Finding detection

    private func parseFinding(_ line: String) -> Finding? {
        let f = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
        guard !f.isEmpty else { return nil }

        // ── SB2: sandbox_check result ──────────────────────────────────────────
        if f[0] == "SB2" {
            guard f.count >= 6 else { return nil }
            let result = Int(f[4]) ?? 0
            // Only flag errors (-1) and unexpected returns (2+); denies (1) are normal
            guard result < 0 || result >= 2 else { return nil }
            return Finding(
                signame: "SANDBOX",
                rawHex: "",
                siCode: result,
                faultAddr: "",
                unknown: false,
                isSandbox: true,
                operation: f[3]
            )
        }

        // ── SB1: instruction execution result ─────────────────────────────────
        guard f.count == 11, f[0] == "SB1" else { return nil }
        let signum     = Int(f[7]) ?? 0
        let disasKnown = Int(f[4]) ?? 1
        let siCode     = Int(f[8]) ?? 0

        // signum=0 on a known instruction → clean expected execution (skip)
        if signum == 0 && disasKnown == 1 { return nil }
        // SIGILL (4) on unknown instruction → expected undefined ARM64 encoding (skip)
        if signum == 4 && disasKnown == 0 { return nil }
        // SIGTRAP with si_code=0 is the dry-run backend's synthetic marker — skip.
        // Real kernel SIGTRAPs always have si_code ≥ 1 (TRAP_BRKPT=1, TRAP_TRACE=2).
        if signum == 5 && siCode == 0 { return nil }

        let signame: String
        switch signum {
        case 0:  signame = "CLEAN  "   // unknown instruction that executed cleanly
        case 4:  signame = "SIGILL "
        case 5:  signame = "SIGTRAP"
        case 7:  signame = "SIGBUS "
        case 8:  signame = "SIGFPE "
        case 11: signame = "SIGSEGV"
        default: signame = "SIG\(signum)   ".prefix(7).description
        }

        return Finding(
            signame: signame,
            rawHex: f[10],
            siCode: siCode,
            faultAddr: f[9],
            unknown: disasKnown == 0,
            isSandbox: false,
            operation: ""
        )
    }
}
