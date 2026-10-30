import SwiftUI

struct ContentView: View {
    @State private var tester = FirewallTester()
    @State private var showRules = false

    var body: some View {
        NavigationStack {
            List {
                Section("Your Firebase project") {
                    TextField("Project ID (e.g. my-app-1234)", text: $tester.projectID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Web API Key", text: $tester.apiKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button {
                        Task { await tester.run() }
                    } label: {
                        HStack {
                            Text(tester.isRunning ? "Attacking…" : "Run Firewall Test")
                            if tester.isRunning { ProgressView() }
                        }
                    }
                    .disabled(tester.isRunning)
                    Button("View rules to paste into Firebase Console") { showRules = true }
                }

                if let error = tester.setupError {
                    Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange) }
                }

                if tester.finished { verdict }

                if !tester.results.isEmpty {
                    Section("Attack attempts (\(tester.passCount)/\(tester.results.count) behaved correctly)") {
                        ForEach(tester.results) { ResultRow(result: $0) }
                    }
                }
            }
            .navigationTitle("Cloud Firewall")
            .sheet(isPresented: $showRules) { RulesSheet() }
        }
    }

    private var verdict: some View {
        Section {
            HStack(spacing: 12) {
                Image(systemName: tester.allPassed ? "checkmark.shield.fill" : "xmark.shield.fill")
                    .font(.largeTitle)
                VStack(alignment: .leading) {
                    Text(tester.allPassed ? "IT WORKS ✅" : "NOT SECURE ❌")
                        .font(.title2.bold())
                    Text(tester.allPassed
                         ? "Users can only read/write records matching their own User ID."
                         : "Some tests failed. Check the red rows and your published rules.")
                        .font(.footnote)
                }
            }
            .foregroundStyle(tester.allPassed ? .green : .red)
        }
    }
}

struct ResultRow: View {
    let result: TestResult

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(color).font(.title3)
            VStack(alignment: .leading, spacing: 2) {
                Text(result.name).font(.headline)
                Text("Expected \(result.expectation.rawValue) · \(result.message)")
                    .font(.caption.monospaced()).foregroundStyle(color)
            }
        }
    }

    private var icon: String {
        switch result.outcome {
        case .pass: "checkmark.circle.fill"
        case .fail: "xmark.octagon.fill"
        case .error: "exclamationmark.triangle.fill"
        case .pending: "circle"
        }
    }
    private var color: Color {
        switch result.outcome {
        case .pass: .green
        case .fail: .red
        case .error: .orange
        case .pending: .gray
        }
    }
}

struct RulesSheet: View {
    @Environment(\.dismiss) private var dismiss

    static let rules = """
    rules_version = '2';
    service cloud.firestore {
      match /databases/{database}/documents {

        match /users/{userId}/{document=**} {
          allow read, write: if request.auth != null
                             && request.auth.uid == userId;
        }

        match /{document=**} {
          allow read, write: if false;
        }
      }
    }
    """

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Firebase Console → Firestore Database → Rules → paste → Publish.")
                        .font(.footnote).foregroundStyle(.secondary)
                    Text(Self.rules)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                    Button("Copy rules") { UIPasteboard.general.string = Self.rules }
                        .buttonStyle(.borderedProminent)
                }
                .padding()
            }
            .navigationTitle("Security Rules")
            .toolbar { Button("Done") { dismiss() } }
        }
    }
}

#Preview {
    ContentView()
}
