import Foundation
import Observation

enum Expectation: String {
    case allow = "ALLOW"
    case deny = "DENY"
}

enum Outcome {
    case pending
    case pass
    case fail
    case error
}

struct TestResult: Identifiable {
    let id = UUID()
    let name: String
    let detail: String
    let expectation: Expectation
    var httpStatus: Int?
    var outcome: Outcome = .pending
    var message: String = ""
}

struct HTTPReply {
    let status: Int
    let body: [String: Any]

    var firebaseStatus: String? {
        (body["error"] as? [String: Any])?["status"] as? String
    }
    var errorMessage: String? {
        (body["error"] as? [String: Any])?["message"] as? String
    }
}

struct Session {
    let uid: String
    let idToken: String
}

@Observable
@MainActor
final class FirewallTester {
    var projectID: String = UserDefaults.standard.string(forKey: "projectID") ?? "cloudfirewall-592d0" {
        didSet { UserDefaults.standard.set(projectID, forKey: "projectID") }
    }
    var apiKey: String = UserDefaults.standard.string(forKey: "apiKey") ?? "AIzaSyDA-vFl9-kNhtq-Q761ExPl20p8WSMNdjo" {
        didSet { UserDefaults.standard.set(apiKey, forKey: "apiKey") }
    }

    var results: [TestResult] = []
    var isRunning = false
    var setupError: String?

    var finished: Bool { !results.isEmpty && !isRunning && setupError == nil }
    var allPassed: Bool { finished && results.allSatisfy { $0.outcome == .pass } }
    var passCount: Int { results.filter { $0.outcome == .pass }.count }

    // MARK: - Run

    func run() async {
        guard !projectID.trimmingCharacters(in: .whitespaces).isEmpty,
              !apiKey.trimmingCharacters(in: .whitespaces).isEmpty else {
            setupError = "Enter your Firebase Project ID and Web API Key first."
            return
        }
        isRunning = true
        setupError = nil
        results = []
        defer { isRunning = false }

        // Two real, separately authenticated users (Anonymous Auth).
        let a: Session, b: Session
        do {
            a = try await signUpAnonymously()
            b = try await signUpAnonymously()
        } catch {
            setupError = "Could not create test users. Make sure Anonymous sign-in is enabled in Firebase Authentication and your Project ID / API key are correct."
            return
        }

        let aDoc = "users/\(a.uid)/profile/main"
        let bDoc = "users/\(b.uid)/profile/main"

        // Order matters: A's document must exist before B tries to read it.
        await check("User A writes own data",
                    "A → PATCH users/A/…", .allow) { await self.write(aDoc, "secret of A", as: a) }

        await check("User A reads own data",
                    "A → GET users/A/…", .allow) { await self.read(aDoc, as: a) }

        await check("User B writes own data",
                    "B → PATCH users/B/… (proves rules aren't just \"deny all\")", .allow) {
            await self.write(bDoc, "secret of B", as: b)
        }

        await check("User B reads User A's data",
                    "B → GET users/A/…  (the attack from the slide)", .deny) { await self.read(aDoc, as: b) }

        await check("User B overwrites User A's data",
                    "B → PATCH users/A/…", .deny) { await self.write(aDoc, "HACKED by B", as: b) }

        await check("User A reads User B's data",
                    "A → GET users/B/…", .deny) { await self.read(bDoc, as: a) }

        await check("Logged-out request reads data",
                    "no token → GET users/A/…", .deny) { await self.read(aDoc, as: nil) }

        await check("Logged-out request writes data",
                    "no token → PATCH users/A/…", .deny) { await self.write(aDoc, "HACKED anon", as: nil) }

        await check("Forged token reads data",
                    "fake token → GET users/A/…", .deny) {
            await self.read(aDoc, as: Session(uid: a.uid, idToken: "eyJhbGciOiJub25lIn0.fake.forged"))
        }

        await check("Authenticated user reads unrelated collection",
                    "A → GET secrets/admin (default-deny)", .deny) { await self.read("secrets/admin", as: a) }

        await check("Authenticated user writes unrelated collection",
                    "A → PATCH secrets/admin (default-deny)", .deny) { await self.write("secrets/admin", "x", as: a) }
    }

    // MARK: - Check helper

    private func check(_ name: String, _ detail: String, _ expect: Expectation,
                       _ request: () async -> HTTPReply) async {
        var result = TestResult(name: name, detail: detail, expectation: expect)
        let reply = await request()
        result.httpStatus = reply.status

        let denied = (reply.status == 403 && reply.firebaseStatus == "PERMISSION_DENIED")
            || reply.status == 401
        let allowed = reply.status == 200

        switch (expect, allowed, denied) {
        case (.allow, true, _):
            result.outcome = .pass
            result.message = "Allowed"
        case (.deny, _, true):
            result.outcome = .pass
            result.message = "Blocked"
        case (.allow, _, true):
            result.outcome = .fail
            result.message = "Wrongly blocked — rules too strict"
        case (.deny, true, _):
            result.outcome = .fail
            result.message = "DATA LEAKED — rules are too open!"
        default:
            result.outcome = .error
            result.message = "Unexpected response — check your Firebase setup"
        }
        results.append(result)
    }

    // MARK: - Firebase REST

    private func signUpAnonymously() async throws -> Session {
        let url = URL(string: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=\(apiKey)")!
        let reply = await send(url: url, method: "POST", token: nil, json: ["returnSecureToken": true])
        guard reply.status == 200,
              let uid = reply.body["localId"] as? String,
              let token = reply.body["idToken"] as? String else {
            throw NSError(domain: "Auth", code: reply.status,
                          userInfo: [NSLocalizedDescriptionKey: reply.errorMessage ?? "HTTP \(reply.status)"])
        }
        return Session(uid: uid, idToken: token)
    }

    private func docURL(_ path: String) -> URL {
        URL(string: "https://firestore.googleapis.com/v1/projects/\(projectID)/databases/(default)/documents/\(path)?key=\(apiKey)")!
    }

    private func read(_ path: String, as session: Session?) async -> HTTPReply {
        await send(url: docURL(path), method: "GET", token: session?.idToken, json: nil)
    }

    private func write(_ path: String, _ value: String, as session: Session?) async -> HTTPReply {
        let body: [String: Any] = ["fields": ["note": ["stringValue": value]]]
        return await send(url: docURL(path), method: "PATCH", token: session?.idToken, json: body)
    }

    private func send(url: URL, method: String, token: String?, json: [String: Any]?) async -> HTTPReply {
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 20
        if let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let json {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: json)
        }
        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
            return HTTPReply(status: status, body: body)
        } catch {
            return HTTPReply(status: 0, body: ["error": ["message": error.localizedDescription]])
        }
    }
}
