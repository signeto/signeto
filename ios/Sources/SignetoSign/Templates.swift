// docs/protocol.md §3: display templates and the renderer. Two inputs only: the canonical bytes as
// received and the template registries. Output is byte-identical to src/template.ts `renderTemplate`.
import Foundation

public struct Template: Equatable, Codable, Sendable {
    public let templateId: String
    public let templateVersion: Int
    public let text: String
    /// SHA-256 (lowercase hex) of the UTF-8 text.
    public let sha256: String
    /// `args_resolved` keys the template intentionally does not mention (§3.4).
    public let elide: [String]?

    public init(templateId: String, templateVersion: Int, text: String, sha256: String, elide: [String]? = nil) {
        self.templateId = templateId
        self.templateVersion = templateVersion
        self.text = text
        self.sha256 = sha256
        self.elide = elide
    }

    /// A template whose `sha256` is computed from its text.
    public init(templateId: String, templateVersion: Int, text: String, elide: [String]? = nil) {
        self.init(templateId: templateId, templateVersion: templateVersion, text: text, sha256: Templates.sha256(text), elide: elide)
    }

    enum CodingKeys: String, CodingKey {
        case templateId = "template_id", templateVersion = "template_version", text, sha256, elide
    }

    public static func == (a: Template, b: Template) -> Bool {
        exactlyEqual(a.templateId, b.templateId) && a.templateVersion == b.templateVersion && exactlyEqual(a.text, b.text) && a.sha256 == b.sha256
            && (a.elide ?? []).count == (b.elide ?? []).count && zip(a.elide ?? [], b.elide ?? []).allSatisfy { exactlyEqual($0, $1) }
    }
}

public struct TemplateRegistry: Equatable, Codable, Sendable {
    public let adapter: String
    public let templates: [Template]

    public init(adapter: String, templates: [Template]) {
        self.adapter = adapter
        self.templates = templates
    }
}

/// A `{template_id, template_version, sha256}` pin from a verified pairing confirmation (§5.4).
public struct TemplatePin: Equatable, Hashable, Codable, Sendable {
    public let templateId: String
    public let templateVersion: Int
    public let sha256: String

    public init(templateId: String, templateVersion: Int, sha256: String) {
        self.templateId = templateId
        self.templateVersion = templateVersion
        self.sha256 = sha256
    }

    enum CodingKeys: String, CodingKey {
        case templateId = "template_id", templateVersion = "template_version", sha256
    }

    public static func == (a: TemplatePin, b: TemplatePin) -> Bool {
        exactlyEqual(a.templateId, b.templateId) && a.templateVersion == b.templateVersion && a.sha256 == b.sha256
    }

    public func hash(into h: inout Hasher) {
        h.combine(Array(templateId.utf8))
        h.combine(templateVersion)
        h.combine(sha256)
    }

    /// The pin as signed in the confirmation: exactly these three members.
    public var json: JSONValue {
        ["sha256": .string(sha256), "template_id": .string(templateId), "template_version": .number(Double(templateVersion))]
    }
}

/// `template_source` sent alongside an approval request (§7.5). Unverified unless pinned (§3.1, §5.4).
public struct TemplateSource: Equatable, Codable, Sendable {
    public let templateId: String
    public let templateVersion: Int
    public let text: String
    public let sha256: String
    public let elide: [String]?

    public init(templateId: String, templateVersion: Int, text: String, sha256: String, elide: [String]? = nil) {
        self.templateId = templateId
        self.templateVersion = templateVersion
        self.text = text
        self.sha256 = sha256
        self.elide = elide
    }

    enum CodingKeys: String, CodingKey {
        case templateId = "template_id", templateVersion = "template_version", text, sha256, elide
    }
}

public enum UnverifiedReason: String, Equatable, Sendable {
    case actionMalformed = "action_malformed"
    case unknownTemplate = "unknown_template"
    case templateHashMismatch = "template_hash_mismatch"
    case malformedTemplate = "malformed_template"
    case unresolvedPlaceholder = "unresolved_placeholder"
    case unreferencedKey = "unreferenced_key"
}

public enum RenderResult: Equatable, Sendable {
    /// The rendered line, the template used, and elided keys present in `args_resolved` (JS key order).
    case ok(text: String, template: Template, hidden: [String])
    /// §3.4 fallback: show the raw canonical bytes as the primary content, marked "unverified template".
    case unverified(reason: UnverifiedReason, detail: String?, canonicalBytes: String)

    public var isVerified: Bool { if case .ok = self { return true } else { return false } }
}

public enum Templates {
    public static func sha256(_ text: String) -> String { Digest.sha256Hex(text) }

    /// The registries bundled with `@signeto/protocol` (github, postgres, alpaca), shipped as data in
    /// `Resources/builtin-registries.json`. Empty (everything renders unverified) if the resource is unreadable.
    public static let builtinRegistries: [TemplateRegistry] = {
        guard let url = Bundle.module.url(forResource: "builtin-registries", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let regs = try? JSONDecoder().decode([TemplateRegistry].self, from: data) else { return [] }
        return regs
    }()

    public static func find(_ registries: [TemplateRegistry], id: String, version: Int) -> Template? {
        for r in registries { for t in r.templates where exactlyEqual(t.templateId, id) && t.templateVersion == version { return t } }
        return nil
    }

    /// Builtin registries plus `template_source`, accepted only when the gateway pinned exactly that
    /// template (id, version, sha256) in its verified pairing confirmation and the text hashes to it.
    /// Same rule as the CLI's `registriesFor`.
    public static func registries(templateSource: TemplateSource?, pinned: [TemplatePin], builtin: [TemplateRegistry] = builtinRegistries) -> [TemplateRegistry] {
        var regs = builtin
        if let src = templateSource, sha256(src.text) == src.sha256,
           pinned.contains(TemplatePin(templateId: src.templateId, templateVersion: src.templateVersion, sha256: src.sha256)) {
            let elide = (src.elide ?? []).isEmpty ? nil : src.elide
            regs.append(TemplateRegistry(adapter: "pinned", templates: [Template(templateId: src.templateId, templateVersion: src.templateVersion, text: src.text, sha256: src.sha256, elide: elide)]))
        }
        return regs
    }

    enum Token: Equatable {
        case literal(String)
        case placeholder([String])
    }

    /// §3.2 grammar. nil on a stray brace or an empty/invalid path.
    static func tokenize(_ text: String) -> [Token]? {
        // Work in UTF-16 code units, as the TS tokenizer indexes a JS string.
        let u = Array(text.utf16)
        var out: [Token] = []
        var lit: [UInt16] = []
        var i = 0
        func flush() {
            if !lit.isEmpty { out.append(.literal(String(decoding: lit, as: UTF16.self))); lit = [] }
        }
        while i < u.count {
            let c = u[i]
            if c == 0x7B { // {
                if i + 1 < u.count, u[i + 1] == 0x7B { lit.append(0x7B); i += 2; continue }
                guard let end = u[(i + 1)...].firstIndex(of: 0x7D) else { return nil }
                let path = Array(u[(i + 1)..<end])
                guard isValidPath(path) else { return nil }
                flush()
                out.append(.placeholder(String(decoding: path, as: UTF16.self).split(separator: ".", omittingEmptySubsequences: false).map(String.init)))
                i = end + 1
                continue
            }
            if c == 0x7D { // }
                if i + 1 < u.count, u[i + 1] == 0x7D { lit.append(0x7D); i += 2; continue }
                return nil
            }
            lit.append(c)
            i += 1
        }
        flush()
        return out
    }

    /// `^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$`
    static func isValidPath(_ p: [UInt16]) -> Bool {
        guard !p.isEmpty else { return false }
        var segLen = 0
        for c in p {
            if c == 0x2E {
                if segLen == 0 { return false }
                segLen = 0
            } else if (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) || c == 0x5F {
                segLen += 1
            } else {
                return false
            }
        }
        return segLen > 0
    }

    static func lookup(_ args: JSONObject, _ path: [String]) -> JSONValue? {
        var cur: JSONValue = .object(args)
        for seg in path {
            switch cur {
            case .array(let a):
                guard seg.utf8.allSatisfy(Chars.isDigit), let idx = Int(seg), idx < a.count else { return nil }
                cur = a[idx]
            case .object(let o):
                guard let v = o[seg] else { return nil }
                cur = v
            default:
                return nil
            }
        }
        return cur
    }

    /// §3.2 value rendering: strings verbatim, everything else as its JCS text.
    public static func renderValue(_ v: JSONValue) -> String {
        if case .string(let s) = v { return s }
        return (try? JCS.canonicalize(v)) ?? ""
    }

    /// Render the template line for canonical bytes.
    public static func render(canonicalBytes: String, registries: [TemplateRegistry]) -> RenderResult {
        let parsed: EncodedAction
        switch CanonicalActions.parse(canonicalBytes) {
        case .failure(let e): return .unverified(reason: .actionMalformed, detail: e.rawValue, canonicalBytes: canonicalBytes)
        case .success(let p): parsed = p
        }
        return render(parsed, registries: registries)
    }

    public static func render(_ parsed: EncodedAction, registries: [TemplateRegistry]) -> RenderResult {
        let a = parsed.action
        let bytes = parsed.canonicalBytes
        guard let t = find(registries, id: a.templateId, version: a.templateVersion) else { return .unverified(reason: .unknownTemplate, detail: nil, canonicalBytes: bytes) }
        guard sha256(t.text) == t.sha256 else { return .unverified(reason: .templateHashMismatch, detail: nil, canonicalBytes: bytes) }
        guard let tokens = tokenize(t.text) else { return .unverified(reason: .malformedTemplate, detail: nil, canonicalBytes: bytes) }

        var referenced = Set<ExactKey>()
        var out = ""
        for tok in tokens {
            switch tok {
            case .literal(let s):
                out += s
            case .placeholder(let path):
                referenced.insert(ExactKey(path[0]))
                guard let v = lookup(a.argsResolved, path) else {
                    return .unverified(reason: .unresolvedPlaceholder, detail: path.joined(separator: "."), canonicalBytes: bytes)
                }
                out += renderValue(v)
            }
        }
        let elide = Set((t.elide ?? []).map(ExactKey.init))
        var hidden: [String] = []
        for k in a.argsResolved.ecmaScriptKeyOrder {
            if referenced.contains(ExactKey(k)) { continue }
            if elide.contains(ExactKey(k)) { hidden.append(k) } else { return .unverified(reason: .unreferencedKey, detail: k, canonicalBytes: bytes) }
        }
        return .ok(text: out, template: t, hidden: hidden)
    }
}
