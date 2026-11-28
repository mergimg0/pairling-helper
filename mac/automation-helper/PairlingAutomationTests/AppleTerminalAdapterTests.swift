import Foundation
import XCTest
@testable import PairlingAutomation

private final class FakeTerminalScriptExecutor: TerminalScriptExecuting {
    struct Invocation: Equatable {
        let handler: String
        let arguments: [String]
    }

    var results: [String: TerminalScriptResult] = [:]
    private(set) var invocations: [Invocation] = []

    func execute(
        _ template: TerminalScriptTemplate,
        arguments: [String]
    ) throws -> TerminalScriptResult {
        invocations.append(.init(handler: template.handler, arguments: arguments))
        return results[template.handler] ?? .string("ok")
    }
}

private final class FakeTerminalProcessFinder: TerminalProcessFinding {
    var processIdentifier: pid_t?

    init(processIdentifier: pid_t?) {
        self.processIdentifier = processIdentifier
    }

    func terminalProcessIdentifier() -> pid_t? {
        processIdentifier
    }
}

private final class TerminalPostingRecorder {
    var events: [String] = []
}

private final class FakeTerminalKeyPoster: TerminalKeyPosting {
    private let recorder: TerminalPostingRecorder?
    private(set) var postedKeys: [(key: TerminalSpecialKey, processIdentifier: pid_t)] = []
    /// The post, counted from one, that fails before posting anything.
    var failsOnPost: Int?

    init(recorder: TerminalPostingRecorder? = nil) {
        self.recorder = recorder
    }

    func post(_ key: TerminalSpecialKey, to processIdentifier: pid_t) throws {
        if failsOnPost == postedKeys.count + 1 {
            throw AppleTerminalAdapterError.keyboardEventUnavailable
        }
        postedKeys.append((key, processIdentifier))
        recorder?.events.append("key:\(key.rawValue)")
    }
}

private final class FakeTerminalTextPoster: TerminalTextPosting {
    private let recorder: TerminalPostingRecorder?
    private(set) var postedTexts: [(text: String, processIdentifier: pid_t)] = []

    init(recorder: TerminalPostingRecorder? = nil) {
        self.recorder = recorder
    }

    func post(_ text: String, to processIdentifier: pid_t) throws {
        postedTexts.append((text, processIdentifier))
        recorder?.events.append("text:\(text)")
    }
}

final class AppleTerminalAdapterTests: XCTestCase {
    func testProbeUsesOnlyTheHarmlessProbeTemplate() throws {
        let executor = FakeTerminalScriptExecutor()
        executor.results["probeTerminal"] = .string("2.15")
        let adapter = makeAdapter(executor: executor)

        try adapter.probe()

        XCTAssertEqual(executor.invocations, [
            .init(handler: "probeTerminal", arguments: []),
        ])
    }

    func testSendTextUsesBracketedPasteForOrdinaryInput() throws {
        let executor = FakeTerminalScriptExecutor()
        let adapter = makeAdapter(executor: executor)

        try adapter.sendText(
            tty: "/dev/ttys001",
            text: "hello\nworld",
            bracketedPaste: true
        )

        XCTAssertEqual(executor.invocations, [
            .init(
                handler: "sendTerminalText",
                arguments: ["/dev/ttys001", "\u{1B}[200~hello\nworld\u{1B}[201~"]
            ),
        ])
    }

    func testSendTextLeavesSingleLineSlashCommandUnwrapped() throws {
        let executor = FakeTerminalScriptExecutor()
        let adapter = makeAdapter(executor: executor)

        try adapter.sendText(
            tty: "/dev/ttys001",
            text: "/model",
            bracketedPaste: false
        )

        XCTAssertEqual(executor.invocations.last, .init(
            handler: "sendTerminalText",
            arguments: ["/dev/ttys001", "/model"]
        ))
    }

    func testSendTextHonorsDaemonBracketingDecisionForSlashPrefixedPath() throws {
        let executor = FakeTerminalScriptExecutor()
        let adapter = makeAdapter(executor: executor)

        try adapter.sendText(
            tty: "/dev/ttys001",
            text: "/tmp/pairling.png - feedback",
            bracketedPaste: true
        )

        XCTAssertEqual(executor.invocations.last, .init(
            handler: "sendTerminalText",
            arguments: [
                "/dev/ttys001",
                "\u{1B}[200~/tmp/pairling.png - feedback\u{1B}[201~",
            ]
        ))
    }

    func testEscapeSelectsExactTabBeforePostingNativeKeyEvent() throws {
        let executor = FakeTerminalScriptExecutor()
        let keyPoster = FakeTerminalKeyPoster()
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster
        )

        try adapter.sendEscape(tty: "/dev/ttys001")

        XCTAssertEqual(executor.invocations, [
            .init(handler: "selectTerminalTab", arguments: ["/dev/ttys001"]),
        ])
        XCTAssertEqual(keyPoster.postedKeys.count, 1)
        XCTAssertEqual(keyPoster.postedKeys.first?.key, .escape)
        XCTAssertEqual(keyPoster.postedKeys.first?.processIdentifier, 42)
    }

    func testAllowedSpecialKeyUsesExactTabAndNativeKeyEvent() throws {
        let executor = FakeTerminalScriptExecutor()
        let keyPoster = FakeTerminalKeyPoster()
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster
        )

        try adapter.sendSpecialKey(tty: "/dev/ttys001", key: "up")

        XCTAssertEqual(executor.invocations, [
            .init(handler: "selectTerminalTab", arguments: ["/dev/ttys001"]),
        ])
        XCTAssertEqual(keyPoster.postedKeys.count, 1)
        XCTAssertEqual(keyPoster.postedKeys.first?.key, .up)
        XCTAssertEqual(keyPoster.postedKeys.first?.processIdentifier, 42)
    }

    func testTypeSegmentsSelectsTheTabOnceAndPostsEverySegmentInOrder() throws {
        let executor = FakeTerminalScriptExecutor()
        executor.results["selectTerminalTabForInput"] = .list([
            "ok", "/dev/ttys001",
        ])
        let recorder = TerminalPostingRecorder()
        let keyPoster = FakeTerminalKeyPoster(recorder: recorder)
        let textPoster = FakeTerminalTextPoster(recorder: recorder)
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster,
            textPoster: textPoster
        )

        try adapter.typeSegments(tty: "/dev/ttys001", segments: [
            .key("down"),
            .key("down"),
            .text("hello\rworld\t"),
            .key("ctrl_c"),
            .text("\r"),
        ])

        XCTAssertEqual(executor.invocations, [
            .init(
                handler: "selectTerminalTabForInput",
                arguments: ["/dev/ttys001"]
            ),
        ])
        XCTAssertEqual(recorder.events, [
            "key:down",
            "key:down",
            "text:hello",
            "key:enter",
            "text:world",
            "key:tab",
            "key:ctrl_c",
            "key:enter",
        ])
        XCTAssertTrue(keyPoster.postedKeys.allSatisfy { $0.processIdentifier == 42 })
    }

    func testTypeSegmentsStopsAtAFailedSegmentAndReportsHowManyCompleted() {
        let executor = FakeTerminalScriptExecutor()
        executor.results["selectTerminalTabForInput"] = .list([
            "ok", "/dev/ttys001",
        ])
        let recorder = TerminalPostingRecorder()
        let keyPoster = FakeTerminalKeyPoster(recorder: recorder)
        keyPoster.failsOnPost = 2
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster,
            textPoster: FakeTerminalTextPoster(recorder: recorder)
        )

        XCTAssertThrowsError(
            try adapter.typeSegments(tty: "/dev/ttys001", segments: [
                .text("a"),
                .key("down"),
                .key("up"),
                .text("b"),
            ])
        ) { error in
            XCTAssertEqual(
                error as? TerminalSegmentsFailure,
                TerminalSegmentsFailure(completedSegments: 2)
            )
        }
        XCTAssertEqual(recorder.events, ["text:a", "key:down"])
        XCTAssertEqual(executor.invocations.count, 1)
    }

    func testTypeSegmentsRefusesAnUnsupportedSegmentBeforeTouchingTheTab() {
        let refused: [[TerminalInputSegment]] = [
            [.text("ok"), .key("return")],
            [.text("ok"), .text("a\u{01}")],
        ]
        for segments in refused {
            let executor = FakeTerminalScriptExecutor()
            let keyPoster = FakeTerminalKeyPoster()
            let textPoster = FakeTerminalTextPoster()
            let adapter = AppleTerminalAdapter(
                scriptExecutor: executor,
                processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
                keyPoster: keyPoster,
                textPoster: textPoster
            )

            XCTAssertThrowsError(
                try adapter.typeSegments(tty: "/dev/ttys001", segments: segments)
            ) { error in
                XCTAssertEqual(error as? AppleTerminalAdapterError, .unsupportedSpecialKey)
            }
            XCTAssertTrue(executor.invocations.isEmpty)
            XCTAssertTrue(keyPoster.postedKeys.isEmpty)
            XCTAssertTrue(textPoster.postedTexts.isEmpty)
        }
    }

    func testTypeSegmentsRejectsAmbiguousTabBeforePosting() {
        let executor = FakeTerminalScriptExecutor()
        executor.results["selectTerminalTabForInput"] = .list(["ambiguous_window"])
        let keyPoster = FakeTerminalKeyPoster()
        let textPoster = FakeTerminalTextPoster()
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster,
            textPoster: textPoster
        )

        XCTAssertThrowsError(
            try adapter.typeSegments(tty: "/dev/ttys001", segments: [.text("hello")])
        ) { error in
            XCTAssertEqual(error as? AppleTerminalAdapterError, .terminalTabAmbiguous)
        }
        XCTAssertTrue(keyPoster.postedKeys.isEmpty)
        XCTAssertTrue(textPoster.postedTexts.isEmpty)
    }

    func testTypeSegmentsRejectsWrongSelectedTTYBeforePosting() {
        let executor = FakeTerminalScriptExecutor()
        executor.results["selectTerminalTabForInput"] = .list([
            "ok", "/dev/ttys999",
        ])
        let keyPoster = FakeTerminalKeyPoster()
        let textPoster = FakeTerminalTextPoster()
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster,
            textPoster: textPoster
        )

        XCTAssertThrowsError(
            try adapter.typeSegments(tty: "/dev/ttys001", segments: [.text("hello")])
        ) { error in
            XCTAssertEqual(error as? AppleTerminalAdapterError, .malformedResponse)
        }
        XCTAssertTrue(keyPoster.postedKeys.isEmpty)
        XCTAssertTrue(textPoster.postedTexts.isEmpty)
    }
    func testEscapeFailsBeforeMutationWhenExactTabIsGone() {
        let executor = FakeTerminalScriptExecutor()
        executor.results["selectTerminalTab"] = .string("no_window")
        let keyPoster = FakeTerminalKeyPoster()
        let adapter = AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: keyPoster
        )

        XCTAssertThrowsError(try adapter.sendEscape(tty: "/dev/ttys001")) { error in
            XCTAssertEqual(error as? AppleTerminalAdapterError, .terminalTabNotFound)
        }
        XCTAssertTrue(keyPoster.postedKeys.isEmpty)
    }

    func testCloseRejectsOwnershipMismatchBeforeMutation() {
        let executor = FakeTerminalScriptExecutor()
        executor.results["closePairlingSession"] = .string("ownership_mismatch")
        let adapter = makeAdapter(executor: executor)

        XCTAssertThrowsError(try adapter.closeOwnedSession(
            tty: "/dev/ttys001",
            ownershipMarker: "pairling:test"
        )) { error in
            XCTAssertEqual(error as? AppleTerminalAdapterError, .ownershipMismatch)
        }
    }

    func testReadTabTruncatesTerminalHistoryToProtocolLimit() throws {
        let executor = FakeTerminalScriptExecutor()
        let oversizedHistory = String(repeating: "x", count: PairlingAutomationConstants.maximumTabContentBytes + 1)
        executor.results["readTerminalTab"] = .list([
            "ok",
            "24",
            "80",
            oversizedHistory,
            "false",
        ])
        let adapter = makeAdapter(executor: executor)

        let snapshot = try adapter.readTab(tty: "/dev/ttys001")

        XCTAssertEqual(snapshot.history.utf8.count, PairlingAutomationConstants.maximumTabContentBytes)
        XCTAssertTrue(snapshot.truncated)
        XCTAssertEqual(snapshot.rows, 24)
        XCTAssertEqual(snapshot.columns, 80)
    }

    private func makeAdapter(executor: FakeTerminalScriptExecutor) -> AppleTerminalAdapter {
        AppleTerminalAdapter(
            scriptExecutor: executor,
            processFinder: FakeTerminalProcessFinder(processIdentifier: 42),
            keyPoster: FakeTerminalKeyPoster()
        )
    }
}
