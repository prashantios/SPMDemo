import XCTest
@testable import SwiftSPM

final class SwiftSPMTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(SwiftSPM().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
