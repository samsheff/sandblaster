import SwiftUI

struct ContentView: View {
    @StateObject private var vm = FuzzerViewModel()

    var body: some View {
        VStack(spacing: 0) {
            headerBar
            Divider().background(Color(white: 0.2))
            logPanel
            Divider().background(Color(white: 0.2))
            findingsPanel
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                Divider().background(Color(white: 0.2))
                controlBar
            }
            .background(Color(white: 0.06))
        }
        .preferredColorScheme(.dark)
    }

    // MARK: - Header

    private var headerBar: some View {
        HStack {
            Text("SANDBLASTER  ios-arm64")
                .font(.system(size: 11, weight: .bold, design: .monospaced))
                .foregroundColor(.white)
            Spacer()
            Text(vm.statusMessage)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.white.opacity(0.6))
                .lineLimit(1)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background {
            // Extend the header background behind the Dynamic Island / notch
            Color(white: 0.08).ignoresSafeArea(edges: .top)
        }
    }

    // MARK: - Log panel

    private var logPanel: some View {
        VStack(spacing: 0) {
            if vm.droppedLineCount > 0 {
                Text("... \(vm.droppedLineCount) older lines trimmed ...")
                    .font(.system(size: 9, design: .monospaced))
                    .foregroundColor(Color(white: 0.45))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 2)
                    .background(Color(white: 0.04))
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(vm.lines.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.white)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 12)
                        }
                        Color.clear.frame(height: 1).id("logBottom")
                    }
                    .padding(.vertical, 4)
                }
                .onChange(of: vm.lines.count) { _ in
                    proxy.scrollTo("logBottom", anchor: .bottom)
                }
            }
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Findings panel

    private var findingsPanel: some View {
        VStack(spacing: 0) {
            HStack {
                Text("FINDINGS")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(.white)
                Spacer()
                Text("\(vm.findings.count)")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(vm.findings.isEmpty ? Color(white: 0.4) : .white)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 5)
            .background(Color(white: 0.1))

            Divider().background(Color(white: 0.15))

            if vm.findings.isEmpty {
                Text("no anomalies yet")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(Color(white: 0.35))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 1) {
                            ForEach(vm.findings) { finding in
                                Text(finding.label)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(colorFor(finding))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .padding(.horizontal, 12)
                            }
                            Color.clear.frame(height: 1).id("findBottom")
                        }
                        .padding(.vertical, 4)
                    }
                    .onChange(of: vm.findings.count) { _ in
                        proxy.scrollTo("findBottom", anchor: .bottom)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity)
        .frame(height: 160)
        .background(Color(white: 0.03))
    }

    private func colorFor(_ f: Finding) -> Color {
        if f.unknown { return Color(red: 1, green: 0.85, blue: 0.4) }
        switch f.signame.trimmingCharacters(in: .whitespaces) {
        case "SIGILL":  return Color(red: 1.0, green: 0.4, blue: 0.4)
        case "SIGSEGV": return Color(red: 1.0, green: 0.5, blue: 0.3)
        case "SIGBUS":  return Color(red: 1.0, green: 0.6, blue: 0.2)
        case "SIGFPE":  return Color(red: 0.9, green: 0.4, blue: 0.9)
        default:        return .white
        }
    }

    // MARK: - Controls

    private var controlBar: some View {
        HStack(spacing: 10) {
            ctrlButton("START", active: !vm.isRunning) { vm.start() }
                .disabled(vm.isRunning)
            ctrlButton("STOP",  active: vm.isRunning)  { vm.stop() }
                .disabled(!vm.isRunning)
            if let url = vm.zipURL, !vm.isRunning {
                ShareLink(item: url) {
                    ctrlLabel("EXPORT", active: true)
                }
            } else {
                ctrlLabel("EXPORT", active: false)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private func ctrlButton(_ label: String, active: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            ctrlLabel(label, active: active)
        }
    }

    private func ctrlLabel(_ label: String, active: Bool) -> some View {
        Text(label)
            .font(.system(size: 14, weight: .bold, design: .monospaced))
            .foregroundColor(active ? .white : Color(white: 0.3))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .overlay(
                RoundedRectangle(cornerRadius: 4)
                    .stroke(active ? Color.white : Color(white: 0.3), lineWidth: 1)
            )
    }
}
