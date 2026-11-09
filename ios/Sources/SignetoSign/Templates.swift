// docs/protocol.md §3: display templates and the renderer. Two inputs only: the canonical bytes as
// received and the template registries. Output is byte-identical to src/template.ts `renderTemplate`.
import Foundation

/// A review link of a template (§3.5): a literal label and a URL template over `args_resolved`.
public struct TemplateLink: Equatable, Hashable, Codable, Sendable {
    public let label: String
    public let url: String

    public init(label: String, url: String) {
        self.label = label
        self.url = url
    }

    public static func == (a: TemplateLink, b: TemplateLink) -> Bool { exactlyEqual(a.label, b.label) && exactlyEqual(a.url, b.url) }
    public func hash(into h: inout Hasher) {
        h.combine(Array(label.utf8))
        h.combine(Array(url.utf8))
    }
}

public struct Template: Equatable, Codable, Sendable {
    public let templateId: String
    public let templateVersion: Int
    public let text: String
    /// SHA-256 (lowercase hex) of the template's hash input (§3.1): the UTF-8 text when text-only, else JCS of all members.
    public let sha256: String
    /// `args_resolved` keys the template intentionally does not mention (§3.4).
    public let elide: [String]?
    /// Optional second line, same placeholder rules as `text` plus `{path:short}` (§3.2).
    public let note: String?
    /// Optional review links, at most 4 (§3.5).
    public let links: [TemplateLink]?
    /// Exact hostnames the links may point to (§3.5).
    public let linkHosts: [String]?

    public init(templateId: String, templateVersion: Int, text: String, sha256: String, elide: [String]? = nil, note: String? = nil, links: [TemplateLink]? = nil, linkHosts: [String]? = nil) {
        self.templateId = templateId
        self.templateVersion = templateVersion
        self.text = text
        self.sha256 = sha256
        self.elide = elide
        self.note = note
        self.links = links
        self.linkHosts = linkHosts
    }

    /// A template whose `sha256` is computed from its members.
    public init(templateId: String, templateVersion: Int, text: String, elide: [String]? = nil, note: String? = nil, links: [TemplateLink]? = nil, linkHosts: [String]? = nil) {
        self.init(templateId: templateId, templateVersion: templateVersion, text: text,
                  sha256: Templates.sha256(text: text, elide: elide, note: note, links: links, linkHosts: linkHosts),
                  elide: elide, note: note, links: links, linkHosts: linkHosts)
    }

    /// The sha256 its members hash to (§3.1); a usable template has `computedSHA256 == sha256`.
    public var computedSHA256: String { Templates.sha256(text: text, elide: elide, note: note, links: links, linkHosts: linkHosts) }

    enum CodingKeys: String, CodingKey {
        case templateId = "template_id", templateVersion = "template_version", text, sha256, elide, note, links, linkHosts = "link_hosts"
    }

    public static func == (a: Template, b: Template) -> Bool {
        exactlyEqual(a.templateId, b.templateId) && a.templateVersion == b.templateVersion && exactlyEqual(a.text, b.text) && a.sha256 == b.sha256
            && Templates.sameStrings(a.elide, b.elide) && Templates.sameStrings(a.linkHosts, b.linkHosts)
            && Templates.sameStrings(a.note.map { [$0] }, b.note.map { [$0] }) && (a.links ?? []) == (b.links ?? [])
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
    public let note: String?
    public let links: [TemplateLink]?
    public let linkHosts: [String]?

    public init(templateId: String, templateVersion: Int, text: String, sha256: String, elide: [String]? = nil, note: String? = nil, links: [TemplateLink]? = nil, linkHosts: [String]? = nil) {
        self.templateId = templateId
        self.templateVersion = templateVersion
        self.text = text
        self.sha256 = sha256
        self.elide = elide
        self.note = note
        self.links = links
        self.linkHosts = linkHosts
    }

    enum CodingKeys: String, CodingKey {
        case templateId = "template_id", templateVersion = "template_version", text, sha256, elide, note, links, linkHosts = "link_hosts"
    }

    /// The template it carries, members normalised (empty lists and an empty note are absent).
    public var template: Template {
        Template(templateId: templateId, templateVersion: templateVersion, text: text, sha256: sha256,
                 elide: (elide ?? []).isEmpty ? nil : elide, note: (note ?? "").isEmpty ? nil : note,
                 links: (links ?? []).isEmpty ? nil : links, linkHosts: (linkHosts ?? []).isEmpty ? nil : linkHosts)
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

/// Why a template's links were dropped as a whole (§3.5). The card itself still renders.
public enum LinksError: String, Error, Equatable, Sendable {
    case linksMalformed = "links_malformed"
    case tooManyLinks = "too_many_links"
    case linkHostsInvalid = "link_hosts_invalid"
    case labelInvalid = "label_invalid"
    case urlInvalid = "url_invalid"
    case urlNotHTTPS = "url_not_https"
    case hostNotLiteral = "host_not_literal"
    case hostNotAllowed = "host_not_allowed"
}

/// A review link built on this device from the verified canonical args (§3.5).
public struct RenderedLink: Equatable, Sendable {
    public let label: String
    /// The final URL string: `https://<allowlisted host>/…`, ASCII only.
    public let url: String
    /// The host, from the template's literal prefix (one of its `link_hosts`).
    public let host: String

    public init(label: String, url: String, host: String) {
        self.label = label
        self.url = url
        self.host = host
    }

    public static func == (a: RenderedLink, b: RenderedLink) -> Bool { exactlyEqual(a.label, b.label) && a.url == b.url && a.host == b.host }
}

/// A verified rendering: the sentence, the template used, elided keys, the note line and the review links.
public struct RenderedTemplate: Equatable, Sendable {
    public let text: String
    public let template: Template
    /// Elided keys present in `args_resolved` (JS key order).
    public let hidden: [String]
    public let note: String?
    public let links: [RenderedLink]
    /// Set when the template's links are invalid and were all dropped: show a warning.
    public let linksError: LinksError?

    public init(text: String, template: Template, hidden: [String], note: String? = nil, links: [RenderedLink] = [], linksError: LinksError? = nil) {
        self.text = text
        self.template = template
        self.hidden = hidden
        self.note = note
        self.links = links
        self.linksError = linksError
    }

    public static func == (a: RenderedTemplate, b: RenderedTemplate) -> Bool {
        exactlyEqual(a.text, b.text) && a.template == b.template && a.hidden == b.hidden && Templates.sameStrings(a.note.map { [$0] }, b.note.map { [$0] })
            && a.links == b.links && a.linksError == b.linksError
    }
}

public enum RenderResult: Equatable, Sendable {
    /// The verified rendering (sentence, note, links).
    case ok(RenderedTemplate)
    /// §3.4 fallback: show the raw canonical bytes as the primary content, marked "unverified template".
    case unverified(reason: UnverifiedReason, detail: String?, canonicalBytes: String)

    public var isVerified: Bool { if case .ok = self { return true } else { return false } }
    public var rendered: RenderedTemplate? { if case .ok(let r) = self { return r } else { return nil } }
}

public enum Templates {
    /// SHA-256 of a text-only template (§3.1): the UTF-8 text.
    public static func sha256(_ text: String) -> String { Digest.sha256Hex(text) }

    public static let maxLinks = 4
    public static let maxLinkHosts = 8
    public static let maxLinkLabelBytes = 64
    public static let maxLinkURLLength = 2048
    /// `{path:short}`: the first 7 code points of a string value (note only).
    public static let shortLength = 7

    /// §3.1 hash input. Text-only: the text itself. Otherwise JCS of `text` and every present member of `elide`,
    /// `note`, `links`, `link_hosts` (empty lists and an empty note count as absent). `elide` widens what the
    /// card hides, so it is always covered.
    public static func hashInput(text: String, elide: [String]?, note: String?, links: [TemplateLink]?, linkHosts: [String]?) -> String {
        let e = (elide ?? []).isEmpty ? nil : elide
        let n = (note ?? "").isEmpty ? nil : note
        let l = (links ?? []).isEmpty ? nil : links
        let h = (linkHosts ?? []).isEmpty ? nil : linkHosts
        if e == nil, n == nil, l == nil, h == nil { return text }
        var o = JSONObject()
        o["text"] = .string(text)
        if let e { o["elide"] = .array(e.map { .string($0) }) }
        if let n { o["note"] = .string(n) }
        if let l { o["links"] = .array(l.map { ["label": .string($0.label), "url": .string($0.url)] }) }
        if let h { o["link_hosts"] = .array(h.map { .string($0) }) }
        return (try? JCS.canonicalize(.object(o))) ?? ""
    }

    public static func sha256(text: String, elide: [String]?, note: String?, links: [TemplateLink]?, linkHosts: [String]?) -> String {
        Digest.sha256Hex(hashInput(text: text, elide: elide, note: note, links: links, linkHosts: linkHosts))
    }

    static func sameStrings(_ a: [String]?, _ b: [String]?) -> Bool {
        let x = a ?? [], y = b ?? []
        return x.count == y.count && zip(x, y).allSatisfy { exactlyEqual($0, $1) }
    }

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
    /// template (id, version, sha256) in its verified pairing confirmation and the template hashes to it.
    /// The hash covers `note`, `links` and `link_hosts`. Same rule as the CLI's `registriesFor`.
    public static func registries(templateSource: TemplateSource?, pinned: [TemplatePin], builtin: [TemplateRegistry] = builtinRegistries) -> [TemplateRegistry] {
        var regs = builtin
        if let src = templateSource {
            let t = src.template
            if t.computedSHA256 == t.sha256, pinned.contains(TemplatePin(templateId: t.templateId, templateVersion: t.templateVersion, sha256: t.sha256)) {
                regs.append(TemplateRegistry(adapter: "pinned", templates: [t]))
            }
        }
        return regs
    }

    enum Token: Equatable {
        case literal(String)
        /// A path into `args_resolved` and an optional formatter (`short`, `path`).
        case placeholder([String], String?)
    }

    /// §3.2 grammar. nil on a stray brace, an empty/invalid path, or a formatter not in `formatters`
    /// (`{path:name}`; `text` allows none, `note` allows `short`, link URLs allow `path`).
    static func tokenize(_ text: String, formatters: [String] = []) -> [Token]? {
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
                let inner = Array(u[(i + 1)..<end])
                // `path(:fmt)?`, fmt `[a-z]+`; the path cannot contain ':', so split at the first one.
                let colon = inner.firstIndex(of: 0x3A)
                let path = colon.map { Array(inner[..<$0]) } ?? inner
                guard isValidPath(path) else { return nil }
                var fmt: String?
                if let colon {
                    let f = Array(inner[(colon + 1)...])
                    guard !f.isEmpty, f.allSatisfy({ $0 >= 0x61 && $0 <= 0x7A }) else { return nil }
                    let name = String(decoding: f, as: UTF16.self)
                    guard formatters.contains(name) else { return nil }
                    fmt = name
                }
                flush()
                out.append(.placeholder(String(decoding: path, as: UTF16.self).split(separator: ".", omittingEmptySubsequences: false).map(String.init), fmt))
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

    // MARK: - §3.5 links

    static func isAlnum(_ c: UInt16) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) }
    static func isHexDigit(_ c: UInt16) -> Bool { (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66) }
    /// RFC 3986 unreserved: ALPHA DIGIT - . _ ~
    static func isUnreserved(_ c: UInt16) -> Bool { isAlnum(c) || c == 0x2D || c == 0x2E || c == 0x5F || c == 0x7E }
    /// `:/?#@!$&'()*+,;=`
    static let urlLiteralExtra: Set<UInt16> = Set(":/?#@!$&'()*+,;=".utf16)

    /// Literal URL characters outside placeholders: unreserved, `:/?#@!$&'()*+,;=`, and `%XX`.
    static func isValidURLLiteral(_ s: String) -> Bool {
        let u = Array(s.utf16)
        var i = 0
        while i < u.count {
            let c = u[i]
            if isUnreserved(c) || urlLiteralExtra.contains(c) { i += 1; continue }
            if c == 0x25, i + 2 < u.count, isHexDigit(u[i + 1]), isHexDigit(u[i + 2]) { i += 3; continue }
            return false
        }
        return true
    }

    /// Lowercase LDH labels of 1–63, at least two labels, the last starting with a letter, at most 253 in all.
    public static func isValidLinkHost(_ h: String) -> Bool {
        let u = Array(h.utf16)
        guard u.count >= 1, u.count <= 253 else { return false }
        let labels = u.split(separator: 0x2E, omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        for l in labels {
            guard l.count >= 1, l.count <= 63 else { return false }
            for (i, c) in l.enumerated() {
                let ok = (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x7A) || (c == 0x2D && i > 0 && i < l.count - 1)
                if !ok { return false }
            }
        }
        let last = labels[labels.count - 1].first!
        return last >= 0x61 && last <= 0x7A
    }

    /// Non-empty, at most 64 UTF-8 bytes, no control (C0, DEL, C1) or bidirectional formatting characters.
    public static func isValidLinkLabel(_ s: String) -> Bool {
        guard !s.isEmpty, s.utf8.count <= maxLinkLabelBytes else { return false }
        for sc in s.unicodeScalars {
            let c = sc.value
            if c <= 0x1F || (c >= 0x7F && c <= 0x9F) || c == 0x200E || c == 0x200F || (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) { return false }
        }
        return true
    }

    struct ParsedLink {
        let label: String
        let host: String
        let tokens: [Token]
    }

    static func parseLinkURL(_ url: String, hosts: [String]) -> Result<(host: String, tokens: [Token]), LinksError> {
        guard url.utf16.count <= maxLinkURLLength, let tokens = tokenize(url, formatters: ["path"]) else { return .failure(.urlInvalid) }
        var fragments = 0
        for case .literal(let l) in tokens {
            guard isValidURLLiteral(l) else { return .failure(.urlInvalid) }
            fragments += l.utf16.filter { $0 == 0x23 }.count
        }
        guard fragments <= 1 else { return .failure(.urlInvalid) }
        // Literals are ASCII from here on.
        guard case .literal(let first)? = tokens.first, first.utf8.starts(with: "https://".utf8) else { return .failure(.urlNotHTTPS) }
        let rest = Array(first.utf8.dropFirst(8))
        guard let slash = rest.firstIndex(of: 0x2F) else { return .failure(.hostNotLiteral) }
        let host = String(decoding: rest[..<slash], as: UTF8.self)
        guard hosts.contains(where: { exactlyEqual($0, host) }) else { return .failure(.hostNotAllowed) }
        return .success((host, tokens))
    }

    static func parseLinks(_ t: Template) -> Result<[ParsedLink], LinksError> {
        let links = t.links ?? [], hosts = t.linkHosts ?? []
        guard links.count <= maxLinks else { return .failure(.tooManyLinks) }
        guard hosts.count <= maxLinkHosts, hosts.allSatisfy(isValidLinkHost), links.isEmpty || !hosts.isEmpty else { return .failure(.linkHostsInvalid) }
        var out: [ParsedLink] = []
        for l in links {
            guard isValidLinkLabel(l.label) else { return .failure(.labelInvalid) }
            switch parseLinkURL(l.url, hosts: hosts) {
            case .failure(let e): return .failure(e)
            case .success(let p): out.append(ParsedLink(label: l.label, host: p.host, tokens: p.tokens))
            }
        }
        return .success(out)
    }

    /// §3.5 template-level link rules: nil when the links (and hosts) are valid or absent.
    public static func linksError(_ t: Template) -> LinksError? {
        if case .failure(let e) = parseLinks(t) { return e }
        return nil
    }

    /// RFC 3986 percent-encoding of the UTF-8 bytes; unreserved characters stay, hex digits uppercase.
    public static func encodeLinkSegment(_ s: String) -> String {
        var out = ""
        for b in s.utf8 {
            if isUnreserved(UInt16(b)) { out.unicodeScalars.append(Unicode.Scalar(b)) } else { out += String(format: "%%%02X", b) }
        }
        return out
    }

    /// One link for these args, or nil when a value does not fit the rules (the link is dropped).
    static func renderLink(_ l: ParsedLink, args: JSONObject) -> String? {
        var out = ""
        for tok in l.tokens {
            switch tok {
            case .literal(let s):
                out += s
            case .placeholder(let path, let fmt):
                guard let v = lookup(args, path) else { return nil }
                let s: String
                switch v {
                case .string(let x): s = x
                case .number where v.intValue != nil: s = renderValue(v)
                default: return nil
                }
                // Split by code point, never by grapheme: a combining mark after '/' must not hide it.
                let segments: [String] = fmt == "path"
                    ? s.unicodeScalars.split(separator: "/", omittingEmptySubsequences: false).map { String(String.UnicodeScalarView($0)) }
                    : [s]
                for seg in segments where seg.isEmpty || exactlyEqual(seg, ".") || exactlyEqual(seg, "..") { return nil }
                out += segments.map(encodeLinkSegment).joined(separator: "/")
            }
        }
        guard out.utf16.count <= maxLinkURLLength, let c = URLComponents(string: out), c.scheme == "https",
              let h = c.host, exactlyEqual(h, l.host), c.user == nil, c.password == nil, c.port == nil else { return nil }
        return out
    }

    /// §3.5: the review links for these args. Invalid links never fail the card; they are dropped with a code.
    public static func renderLinks(_ t: Template, args: JSONObject) -> (links: [RenderedLink], error: LinksError?) {
        switch parseLinks(t) {
        case .failure(let e): return ([], e)
        case .success(let parsed): return (parsed.compactMap { p in renderLink(p, args: args).map { RenderedLink(label: p.label, url: $0, host: p.host) } }, nil)
        }
    }

    /// Substitute values; `:short` takes the first 7 code points of a string. `.failure(path)` when unresolved.
    static func substitute(_ tokens: [Token], args: JSONObject) -> Result<String, PathError> {
        var out = ""
        for tok in tokens {
            switch tok {
            case .literal(let s):
                out += s
            case .placeholder(let path, let fmt):
                guard let v = lookup(args, path) else { return .failure(PathError(path: path.joined(separator: "."))) }
                if fmt == "short" {
                    guard case .string(let x) = v else { return .failure(PathError(path: path.joined(separator: "."))) }
                    var view = String.UnicodeScalarView()
                    view.append(contentsOf: x.unicodeScalars.prefix(shortLength))
                    out += String(view)
                } else {
                    out += renderValue(v)
                }
            }
        }
        return .success(out)
    }

    struct PathError: Error { let path: String }

    /// §3.4 unreferenced-key rule, nested (mirrors `unreferenced` in `@signeto/protocol`): every leaf of
    /// `args_resolved` (a scalar, or an empty object or array) must be under a `text` placeholder path, unless its
    /// top-level key is elided. Objects in ECMAScript key order, arrays by index. Returns the first uncovered leaf as
    /// a dotted path, and the elided top-level keys no placeholder names exactly.
    static func unreferenced(_ args: JSONObject, refs: [[String]], elide: Set<ExactKey>) -> (path: String?, hidden: [String]) {
        func covered(_ path: [String]) -> Bool {
            refs.contains { r in r.count <= path.count && zip(r, path).allSatisfy { exactlyEqual($0, $1) } }
        }
        func walk(_ v: JSONValue, _ path: [String]) -> String? {
            if covered(path) { return nil }
            switch v {
            case .array(let items) where !items.isEmpty:
                for (i, item) in items.enumerated() { if let r = walk(item, path + [String(i)]) { return r } }
                return nil
            case .object(let o) where !o.isEmpty:
                for k in o.ecmaScriptKeyOrder { if let r = walk(o[k]!, path + [k]) { return r } }
                return nil
            default:
                return path.joined(separator: ".")
            }
        }
        var hidden: [String] = []
        for k in args.ecmaScriptKeyOrder {
            if covered([k]) { continue }
            if elide.contains(ExactKey(k)) { hidden.append(k); continue }
            if let r = walk(args[k]!, [k]) { return (r, hidden) }
        }
        return (nil, hidden)
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
        guard t.computedSHA256 == t.sha256 else { return .unverified(reason: .templateHashMismatch, detail: nil, canonicalBytes: bytes) }
        let hasNote = !(t.note ?? "").isEmpty
        guard let tokens = tokenize(t.text), let noteTokens = hasNote ? tokenize(t.note!, formatters: ["short"]) : [] else {
            return .unverified(reason: .malformedTemplate, detail: nil, canonicalBytes: bytes)
        }
        let text: String, note: String
        switch substitute(tokens, args: a.argsResolved) {
        case .failure(let e): return .unverified(reason: .unresolvedPlaceholder, detail: e.path, canonicalBytes: bytes)
        case .success(let s): text = s
        }
        switch substitute(noteTokens, args: a.argsResolved) {
        case .failure(let e): return .unverified(reason: .unresolvedPlaceholder, detail: e.path, canonicalBytes: bytes)
        case .success(let s): note = s
        }
        // Only `text` placeholders count: the sentence must mention every argument (§3.4), not the note or a link.
        var refs: [[String]] = []
        for case .placeholder(let path, _) in tokens { refs.append(path) }
        let u = unreferenced(a.argsResolved, refs: refs, elide: Set((t.elide ?? []).map(ExactKey.init)))
        if let path = u.path { return .unverified(reason: .unreferencedKey, detail: path, canonicalBytes: bytes) }
        let hidden = u.hidden
        let links = renderLinks(t, args: a.argsResolved)
        // §3.6: the line and the note show control, bidi and invisible characters as escapes.
        return .ok(RenderedTemplate(text: Display.escape(text), template: t, hidden: hidden, note: hasNote ? Display.escape(note) : nil, links: links.links, linksError: links.error))
    }
}
