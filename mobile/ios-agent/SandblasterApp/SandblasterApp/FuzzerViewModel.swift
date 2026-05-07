import Foundation
import SwiftUI

struct Finding: Identifiable {
    let id = UUID()
    let signame: String
    let rawHex: String
    let siCode: Int
    let faultAddr: String
    let unknown: Bool

    var label: String {
        if unknown && signame == "SIGTRAP" {
            return "[\(signame)]  \(rawHex)  (undocumented)"
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

    private let maxDisplayLines = 300
    private var pollTimer: Timer?
    private var logFileHandle: FileHandle?
    private var findingsFileHandle: FileHandle?
    private var logURL: URL?
    private var findingsURL: URL?
    private let pollBuf = UnsafeMutablePointer<UInt8>.allocate(capacity: 8192)

    deinit {
        pollBuf.deallocate()
    }

    // MARK: - Public interface

    func start() {
        guard !isRunning else { return }
        let result = sandblaster_scan_start(0)
        guard result == 0 else {
            statusMessage = "Failed to start (code \(result))"
            return
        }
        openOutputFiles()
        lines = []
        findings = []
        droppedLineCount = 0
        zipURL = nil
        isRunning = true
        statusMessage = "Running..."
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
        isRunning = false
        statusMessage = "Stopped — \(lines.count) packets, \(findings.count) findings"
        buildZip()
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
            } else {
                pollTimer?.invalidate()
                pollTimer = nil
                flushAndClose()
                isRunning = false
                statusMessage = "Done — \(lines.count + newLines.count) packets, \(findings.count) findings"
                buildZip()
                break
            }
        }
        guard !newLines.isEmpty else { return }

        writeLogsToFile(newLines)

        for line in newLines {
            if let f = parseFinding(line) {
                findings.append(f)
                writeFindingToFile(f)
            }
        }

        lines.append(contentsOf: newLines)
        let excess = lines.count - maxDisplayLines
        if excess > 0 {
            lines.removeFirst(excess)
            droppedLineCount += excess
        }
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

        // Append findings count footer to the findings file text
        var findingsData = (try? Data(contentsOf: fURL)) ?? Data()
        let footer = "# Total findings: \(findings.count)\n"
        findingsData += footer.data(using: .utf8)!

        do {
            let logsData = try Data(contentsOf: lURL)
            let zipData = makeZip(entries: [
                ("logs.txt", logsData),
                ("findings.txt", findingsData)
            ])
            try zipData.write(to: zURL)
            zipURL = zURL
        } catch {
            zipURL = lURL
        }
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
        guard f.count == 11, f[0] == "SB1" else { return nil }
        let signum     = Int(f[7]) ?? 0
        let disasKnown = Int(f[4]) ?? 1
        let siCode     = Int(f[8]) ?? 0

        if signum == 5 && disasKnown == 1 { return nil }

        let signame: String
        switch signum {
        case 4:  signame = "SIGILL "
        case 11: signame = "SIGSEGV"
        case 7:  signame = "SIGBUS "
        case 8:  signame = "SIGFPE "
        case 5:  signame = "SIGTRAP"
        case 0:  signame = "CLEAN  "
        default: signame = "SIG\(signum)   ".prefix(7).description
        }

        return Finding(
            signame: signame,
            rawHex: f[10],
            siCode: siCode,
            faultAddr: f[9],
            unknown: disasKnown == 0
        )
    }
}
