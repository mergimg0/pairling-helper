import Foundation
import XCTest
@testable import PairlingAutomation

final class TerminalScriptTemplateTests: XCTestCase {
    func testHandlerReceivesUntrustedTextAsAppleEventData() throws {
        let template = TerminalScriptTemplate(
            handler: "echoText",
            source: """
            on echoText(value)
                return value
            end echoText
            """
        )
        let untrustedText = "\"; do shell script \"id\"; \""

        let result = try SystemTerminalScriptExecutor().execute(
            template,
            arguments: [untrustedText]
        )

        XCTAssertEqual(result.stringValue, untrustedText)
    }

    func testFixedTemplateDoesNotIncludeUntrustedArgumentsInSource() {
        let template = TerminalScriptTemplate.probeTerminal
        let untrustedText = "\"; do shell script \"id\"; \""

        XCTAssertFalse(template.source.contains(untrustedText))
        XCTAssertEqual(template.handler, "probeTerminal")
    }

    func testSpecialKeyTemplateActivatesTheMatchedTerminalWindowBeforeSelection() throws {
        let source = TerminalScriptTemplate.selectTerminalTab.source
        guard let activate = source.range(of: "activate"),
              let frontmost = source.range(of: "set index of w to 1"),
              let selection = source.range(of: "set selected tab of w to t"),
              let success = source.range(of: "return \"ok\"", range: selection.upperBound..<source.endIndex)
        else {
            return XCTFail("The special-key template must activate, front, select, and confirm the matched Terminal tab.")
        }

        XCTAssertLessThan(activate.lowerBound, frontmost.lowerBound)
        XCTAssertLessThan(frontmost.lowerBound, selection.lowerBound)
        XCTAssertLessThan(selection.lowerBound, success.lowerBound)
    }
}
