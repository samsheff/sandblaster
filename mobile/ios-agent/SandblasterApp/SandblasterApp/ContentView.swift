import SwiftUI

struct ContentView: View {
    @StateObject private var vm = FuzzerViewModel()

    var body: some View {
        VStack(spacing: 0) {
            headerBar
            Divider().background(Color(white: 0.2))
            logPanel
            Divider().background(Color(white: 0.2))
            statsBar
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
            VStack(alignment: .leading, spacing: 2) {
                Text("SANDBLASTER  ios-arm64")
                    .font(.system(size: 11, weight: .bold, design: .monospaced))
                    .foregroundColor(.white)
                if vm.isRunning || vm.executedCount > 0 {
                    Text(vm.backendMode)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(vm.backendMode.contains("DRYRUN")
                            ? Color(red: 1.0, green: 0.6, blue: 0.2)
                            : Color(white: 0.5))
                }
            }
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

    // MARK: - Stats bar

    private var statsBar: some View {
        let rate = vm.execRate >= 1000
            ? String(format: "%.1fk/s", vm.execRate / 1000)
            : String(format: "%.0f/s", vm.execRate)
        let total = vm.executedCount.formatted()
        let queue = vm.queueCapacity == 0 ? "—" : "\(vm.queueDepth)/\(vm.queueCapacity)"
        return HStack(spacing: 0) {
            statCell("RATE",     rate)
            statCell("TOTAL",    total)
            statCell("FINDINGS", "\(vm.findings.count)")
            statCell("QUEUE",    queue)
        }
        .frame(maxWidth: .infinity)
        .background(Color(white: 0.07))
    }

    private func statCell(_ label: String, _ value: String) -> some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.system(size: 9, weight: .bold, design: .monospaced))
                .foregroundColor(Color(white: 0.45))
            Text(value)
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.white)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 4)
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
        if f.isSandbox { return Color(red: 0.7, green: 0.5, blue: 1.0) }
        switch f.signame.trimmingCharacters(in: .whitespaces) {
        case "CLEAN":   return Color(red: 0.4, green: 1.0, blue: 0.9)  // most exciting
        case "SIGILL":  return Color(red: 1.0, green: 0.4, blue: 0.4)
        case "SIGSEGV": return Color(red: 1.0, green: 0.5, blue: 0.3)
        case "SIGBUS":  return Color(red: 1.0, green: 0.6, blue: 0.2)
        case "SIGFPE":  return Color(red: 0.9, green: 0.4, blue: 0.9)
        case "SIGTRAP": return Color(red: 1.0, green: 0.85, blue: 0.4)
        default:        return .white
        }
    }

    // MARK: - Controls

    private var controlBar: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Picker("Mode", selection: $vm.selectedMode) {
                    ForEach(FuzzerMode.allCases) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(vm.isRunning)

                Picker("Strategy", selection: $vm.selectedStrategy) {
                    ForEach(FuzzerStrategy.allCases) { strategy in
                        Text(strategy.label).tag(strategy)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(vm.isRunning || vm.selectedMode == .sandbox)
            }

            HStack(spacing: 8) {
                configField("START", text: $vm.startHex)
                configField("END", text: $vm.endHex)
                configField("SEED", text: $vm.seedText)
                configField("MAX", text: $vm.maxPacketsText)
            }

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
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }

    private func configField(_ label: String, text: Binding<String>) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 8, weight: .bold, design: .monospaced))
                .foregroundColor(Color(white: 0.45))
            TextField("", text: text)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .disabled(vm.isRunning)
                .padding(.horizontal, 6)
                .padding(.vertical, 5)
                .background(Color(white: 0.02))
                .overlay(
                    RoundedRectangle(cornerRadius: 4)
                        .stroke(Color(white: 0.25), lineWidth: 1)
                )
        }
        .frame(maxWidth: .infinity)
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
