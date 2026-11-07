import Foundation
import XCTest
@testable import SignetoSign

/// Shared conformance vectors (`public/packages/protocol/vectors/`) and this package's fixtures, located
/// relative to this file so `swift test` works from any working directory.
enum Paths {
    static let testsDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    static let fixtures = testsDir.appendingPathComponent("Fixtures")
    /// Tests/SignetoSignTests → Tests → ios → public
    static let vectors = testsDir.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("packages/protocol/vectors")
}

func loadJSON(_ url: URL, file: StaticString = #filePath, line: UInt = #line) throws -> JSONValue {
    let data = try Data(contentsOf: url)
    return try JSONParser.parse(data: data)
}

/// Every `*.json` in a vector directory, sorted by name.
func vectors(_ dir: String) throws -> [(name: String, v: JSONValue)] {
    let d = Paths.vectors.appendingPathComponent(dir)
    let names = try FileManager.default.contentsOfDirectory(atPath: d.path).filter { $0.hasSuffix(".json") }.sorted()
    XCTAssertFalse(names.isEmpty, "no vectors in \(dir)")
    return try names.map { ($0, try loadJSON(d.appendingPathComponent($0))) }
}

func fixture(_ name: String) throws -> JSONValue { try loadJSON(Paths.fixtures.appendingPathComponent(name)) }

func vectorKey(_ name: String) throws -> JSONValue { try loadJSON(Paths.vectors.appendingPathComponent("keys/\(name).json")) }

extension JSONValue {
    var s: String { stringValue ?? "<not a string>" }
    func jwk() -> PublicJWK? { PublicJWK(json: self, allowExtraMembers: false) }
    /// A JWK that may carry `d`: return the public half.
    func publicHalf() -> PublicJWK? {
        guard var o = objectValue else { return nil }
        o["d"] = nil
        return PublicJWK(json: .object(o))
    }
}

/// Software P-256 signer from a vector key file (`d` present).
func vectorP256Signer(_ name: String) throws -> SoftwareP256Signer {
    let k = try vectorKey(name)
    return try SoftwareP256Signer(jwkD: k["d"]!.s, expected: k.publicHalf())
}
