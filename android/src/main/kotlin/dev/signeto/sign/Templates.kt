// docs/protocol.md §3: display templates and the renderer. Two inputs only: the canonical bytes as
// received and the template registries. Output is byte-identical to src/template.ts `renderTemplate`.
// Port of SignetoSign Templates.swift.
package dev.signeto.sign

/** A review link of a template (§3.5): a literal label and a URL template over `args_resolved`. */
data class TemplateLink(val label: String, val url: String) {
    val json: JsonValue get() = JsonValue.obj("label" to JsonValue.of(label), "url" to JsonValue.of(url))

    companion object {
        fun fromJson(v: JsonValue?): TemplateLink? {
            val o = v?.objectValue ?: return null
            return TemplateLink(o["label"]?.stringValue ?: return null, o["url"]?.stringValue ?: return null)
        }
    }
}

class Template(
    val templateId: String,
    val templateVersion: Long,
    val text: String,
    /** SHA-256 (lowercase hex) of the template's hash input (§3.1): the UTF-8 text when text-only, else JCS of all members. */
    val sha256: String,
    /** `args_resolved` keys the template intentionally does not mention (§3.4). */
    val elide: List<String>? = null,
    /** Optional second line, same placeholder rules as `text` plus `{path:short}` (§3.2). */
    val note: String? = null,
    /** Optional review links, at most 4 (§3.5). */
    val links: List<TemplateLink>? = null,
    /** Exact hostnames the links may point to (§3.5). */
    val linkHosts: List<String>? = null,
) {
    /**
     * The sha256 its members hash to (§3.1); a usable template has `computedSha256 == sha256`. "" when the members
     * cannot be canonicalized (a lone surrogate), which never equals a real hash.
     */
    val computedSha256: String get() = Templates.sha256(text, elide, note, links, linkHosts)

    /** True when `sha256` is a SHA-256 and the members hash to it. */
    val hashMatches: Boolean get() = Chars.hex64(sha256) && computedSha256 == sha256

    /** Absent members are left out, as Swift's Codable and JSON.stringify do. */
    val json: JsonValue
        get() {
            val m = ArrayList<Pair<String, JsonValue>>()
            m += "template_id" to JsonValue.of(templateId)
            m += "template_version" to JsonValue.of(templateVersion)
            m += "text" to JsonValue.of(text)
            m += "sha256" to JsonValue.of(sha256)
            elide?.let { e -> m += "elide" to JsonValue.of(e.map { JsonValue.of(it) }) }
            note?.let { m += "note" to JsonValue.of(it) }
            links?.let { l -> m += "links" to JsonValue.of(l.map { it.json }) }
            linkHosts?.let { h -> m += "link_hosts" to JsonValue.of(h.map { JsonValue.of(it) }) }
            return JsonValue.Obj(JsonObject(m))
        }

    /** Empty `elide`, `links` and `link_hosts` equal absent ones; an empty note does not equal an absent one. */
    override fun equals(other: Any?): Boolean =
        other is Template && templateId == other.templateId && templateVersion == other.templateVersion && text == other.text &&
            sha256 == other.sha256 && (elide ?: emptyList<String>()) == (other.elide ?: emptyList<String>()) &&
            (linkHosts ?: emptyList<String>()) == (other.linkHosts ?: emptyList<String>()) && note == other.note &&
            (links ?: emptyList<TemplateLink>()) == (other.links ?: emptyList<TemplateLink>())

    override fun hashCode(): Int = listOf(templateId, templateVersion, text, sha256).hashCode()
    override fun toString(): String = "Template($templateId v$templateVersion)"

    companion object {
        /** A template whose `sha256` is computed from its members. */
        fun computed(
            templateId: String,
            templateVersion: Long,
            text: String,
            elide: List<String>? = null,
            note: String? = null,
            links: List<TemplateLink>? = null,
            linkHosts: List<String>? = null,
        ): Template = Template(templateId, templateVersion, text, Templates.sha256(text, elide, note, links, linkHosts), elide, note, links, linkHosts)

        /** From registry JSON (`template_id`, `template_version`, `text`, `sha256`, optional members); null on a bad shape. */
        fun fromJson(v: JsonValue?): Template? {
            val o = v?.objectValue ?: return null
            val f = TemplateFields.parse(o) ?: return null
            return Template(f.templateId, f.templateVersion, f.text, f.sha256, f.elide, f.note, f.links, f.linkHosts)
        }
    }
}

/** The members shared by registry templates and `template_source`, decoded as Swift's Codable would. */
internal class TemplateFields(
    val templateId: String,
    val templateVersion: Long,
    val text: String,
    val sha256: String,
    val elide: List<String>?,
    val note: String?,
    val links: List<TemplateLink>?,
    val linkHosts: List<String>?,
) {
    companion object {
        fun parse(o: JsonObject): TemplateFields? {
            val id = o["template_id"]?.stringValue ?: return null
            val ver = o["template_version"]?.intValue ?: return null
            val text = o["text"]?.stringValue ?: return null
            val sha = o["sha256"]?.stringValue ?: return null
            fun strings(k: String): Result<List<String>?> {
                val v = o[k]
                if (v == null || v.isNull) return Result.success(null)
                val a = v.arrayValue ?: return Result.failure(IllegalArgumentException(k))
                return Result.success(a.map { it.stringValue ?: return Result.failure(IllegalArgumentException(k)) })
            }
            val elide = strings("elide").getOrElse { return null }
            val hosts = strings("link_hosts").getOrElse { return null }
            val noteV = o["note"]
            val note = if (noteV == null || noteV.isNull) null else noteV.stringValue ?: return null
            val linksV = o["links"]
            val links = if (linksV == null || linksV.isNull) {
                null
            } else {
                (linksV.arrayValue ?: return null).map { TemplateLink.fromJson(it) ?: return null }
            }
            return TemplateFields(id, ver, text, sha, elide, note, links, hosts)
        }
    }
}

data class TemplateRegistry(val adapter: String, val templates: List<Template>) {
    val json: JsonValue get() = JsonValue.obj("adapter" to JsonValue.of(adapter), "templates" to JsonValue.of(templates.map { it.json }))

    companion object {
        fun fromJson(v: JsonValue?): TemplateRegistry? {
            val o = v?.objectValue ?: return null
            val adapter = o["adapter"]?.stringValue ?: return null
            val ts = (o["templates"]?.arrayValue ?: return null).map { Template.fromJson(it) ?: return null }
            return TemplateRegistry(adapter, ts)
        }

        /** A JSON array of registries; null when any entry is malformed. */
        fun listFromJson(v: JsonValue?): List<TemplateRegistry>? = v?.arrayValue?.map { fromJson(it) ?: return null }
    }
}

/** A `{template_id, template_version, sha256}` pin from a verified pairing confirmation (§5.4). */
data class TemplatePin(val templateId: String, val templateVersion: Long, val sha256: String) {
    /** The pin as signed in the confirmation: exactly these three members. */
    val json: JsonValue
        get() = JsonValue.obj("sha256" to JsonValue.of(sha256), "template_id" to JsonValue.of(templateId), "template_version" to JsonValue.of(templateVersion))
}

/** `template_source` sent alongside an approval request (§7.5). Unverified unless pinned (§3.1, §5.4). */
data class TemplateSource(
    val templateId: String,
    val templateVersion: Long,
    val text: String,
    val sha256: String,
    val elide: List<String>? = null,
    val note: String? = null,
    val links: List<TemplateLink>? = null,
    val linkHosts: List<String>? = null,
) {
    /** The template it carries, members normalised (empty lists and an empty note are absent). */
    val template: Template
        get() = Template(
            templateId, templateVersion, text, sha256,
            elide = elide?.takeIf { it.isNotEmpty() },
            note = note?.takeIf { it.isNotEmpty() },
            links = links?.takeIf { it.isNotEmpty() },
            linkHosts = linkHosts?.takeIf { it.isNotEmpty() },
        )

    companion object {
        /** From an approval request's `template_source`; null when absent or malformed. */
        fun fromJson(v: JsonValue?): TemplateSource? {
            val o = v?.objectValue ?: return null
            val f = TemplateFields.parse(o) ?: return null
            return TemplateSource(f.templateId, f.templateVersion, f.text, f.sha256, f.elide, f.note, f.links, f.linkHosts)
        }
    }
}

enum class UnverifiedReason(val code: String) {
    ACTION_MALFORMED("action_malformed"),
    UNKNOWN_TEMPLATE("unknown_template"),
    TEMPLATE_HASH_MISMATCH("template_hash_mismatch"),
    MALFORMED_TEMPLATE("malformed_template"),
    UNRESOLVED_PLACEHOLDER("unresolved_placeholder"),
    UNREFERENCED_KEY("unreferenced_key"),
}

/** Why a template's links were dropped as a whole (§3.5). The card itself still renders. */
enum class LinksError(val code: String) {
    LINKS_MALFORMED("links_malformed"),
    TOO_MANY_LINKS("too_many_links"),
    LINK_HOSTS_INVALID("link_hosts_invalid"),
    LABEL_INVALID("label_invalid"),
    URL_INVALID("url_invalid"),
    URL_NOT_HTTPS("url_not_https"),
    HOST_NOT_LITERAL("host_not_literal"),
    HOST_NOT_ALLOWED("host_not_allowed"),
}

/** A review link built on this device from the verified canonical args (§3.5). */
data class RenderedLink(
    val label: String,
    /** The final URL string: `https://<allowlisted host>/…`, ASCII only. */
    val url: String,
    /** The host, from the template's literal prefix (one of its `link_hosts`). */
    val host: String,
)

/** A verified rendering: the sentence, the template used, elided keys, the note line and the review links. */
data class RenderedTemplate(
    val text: String,
    val template: Template,
    /** Elided keys present in `args_resolved` (JS key order). */
    val hidden: List<String>,
    val note: String? = null,
    val links: List<RenderedLink> = emptyList(),
    /** Set when the template's links are invalid and were all dropped: show a warning. */
    val linksError: LinksError? = null,
)

sealed class RenderResult {
    /** The verified rendering (sentence, note, links). */
    data class Ok(val rendered: RenderedTemplate) : RenderResult()

    /** §3.4 fallback: show the raw canonical bytes as the primary content, marked "unverified template". */
    data class Unverified(val reason: UnverifiedReason, val detail: String?, val canonicalBytes: String) : RenderResult()

    val isVerified: Boolean get() = this is Ok
    val renderedOrNull: RenderedTemplate? get() = (this as? Ok)?.rendered
}

object Templates {
    /** SHA-256 of a text-only template (§3.1): the UTF-8 text ("" for text with a lone surrogate: never a match). */
    fun sha256(text: String): String = if (Chars.hasLoneSurrogate(text)) "" else Digest.sha256Hex(text)

    const val MAX_LINKS = 4
    const val MAX_LINK_HOSTS = 8
    const val MAX_LINK_LABEL_BYTES = 64
    const val MAX_LINK_URL_LENGTH = 2048

    /** `{path:short}`: the first 7 code points of a string value (note only). */
    const val SHORT_LENGTH = 7

    /**
     * §3.1 hash input. Text-only: the text itself. Otherwise JCS of `text` and every present member of `elide`,
     * `note`, `links`, `link_hosts` (empty lists and an empty note count as absent). `elide` widens what the card hides,
     * so it is always covered.
     */
    fun hashInput(text: String, elide: List<String>?, note: String?, links: List<TemplateLink>?, linkHosts: List<String>?): String? {
        val e = elide?.takeIf { it.isNotEmpty() }
        val n = note?.takeIf { it.isNotEmpty() }
        val l = links?.takeIf { it.isNotEmpty() }
        val h = linkHosts?.takeIf { it.isNotEmpty() }
        if (e == null && n == null && l == null && h == null) return text
        val m = ArrayList<Pair<String, JsonValue>>()
        m += "text" to JsonValue.of(text)
        e?.let { m += "elide" to JsonValue.of(it.map { s -> JsonValue.of(s) }) }
        n?.let { m += "note" to JsonValue.of(it) }
        l?.let { m += "links" to JsonValue.of(it.map { x -> x.json }) }
        h?.let { m += "link_hosts" to JsonValue.of(it.map { s -> JsonValue.of(s) }) }
        return try {
            Jcs.canonicalize(JsonValue.Obj(JsonObject(m)))
        } catch (_: JcsException) {
            null
        }
    }

    /** The §3.1 hash, or "" when the members cannot be canonicalized (a lone surrogate): never a match. */
    fun sha256(text: String, elide: List<String>?, note: String?, links: List<TemplateLink>?, linkHosts: List<String>?): String {
        if (Chars.hasLoneSurrogate(text)) return ""
        val input = hashInput(text, elide, note, links, linkHosts) ?: return ""
        return Digest.sha256Hex(input)
    }

    /**
     * The registries bundled with `@signeto/protocol` (github, postgres, alpaca), shipped as data in
     * `dev/signeto/sign/builtin-registries.json` (the same file as the Swift package's resource). Empty (everything
     * renders unverified) if the resource is unreadable.
     */
    val builtinRegistries: List<TemplateRegistry> by lazy {
        try {
            val bytes = Templates::class.java.getResourceAsStream("/dev/signeto/sign/builtin-registries.json")?.use { it.readBytes() }
            bytes?.let { TemplateRegistry.listFromJson(JsonParser.parse(it)) } ?: emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun find(registries: List<TemplateRegistry>, id: String, version: Long): Template? {
        for (r in registries) for (t in r.templates) if (t.templateId == id && t.templateVersion == version) return t
        return null
    }

    /**
     * Builtin registries plus `template_source`, accepted only when the gateway pinned exactly that template (id,
     * version, sha256) in its verified pairing confirmation and the template hashes to it. The hash covers `note`,
     * `links` and `link_hosts`. Same rule as the CLI's `registriesFor`.
     */
    fun registries(templateSource: TemplateSource?, pinned: List<TemplatePin>, builtin: List<TemplateRegistry> = builtinRegistries): List<TemplateRegistry> {
        val regs = builtin.toMutableList()
        if (templateSource != null) {
            val t = templateSource.template
            if (t.hashMatches && pinned.contains(TemplatePin(t.templateId, t.templateVersion, t.sha256))) {
                regs += TemplateRegistry("pinned", listOf(t))
            }
        }
        return regs
    }

    internal sealed class Token {
        data class Literal(val text: String) : Token()

        /** A path into `args_resolved` and an optional formatter (`short`, `path`). */
        data class Placeholder(val path: List<String>, val fmt: String?) : Token()
    }

    /**
     * §3.2 grammar. null on a stray brace, an empty/invalid path, or a formatter not in `formatters`
     * (`{path:name}`; `text` allows none, `note` allows `short`, link URLs allow `path`). Works in UTF-16 code units,
     * as the TS tokenizer indexes a JS string.
     */
    internal fun tokenize(text: String, formatters: List<String> = emptyList()): List<Token>? {
        val out = ArrayList<Token>()
        val lit = StringBuilder()
        fun flush() {
            if (lit.isNotEmpty()) {
                out += Token.Literal(lit.toString())
                lit.setLength(0)
            }
        }
        var i = 0
        while (i < text.length) {
            val c = text[i]
            if (c == '{') {
                if (i + 1 < text.length && text[i + 1] == '{') { lit.append('{'); i += 2; continue }
                val end = text.indexOf('}', i + 1)
                if (end < 0) return null
                val inner = text.substring(i + 1, end)
                // `path(:fmt)?`, fmt `[a-z]+`; the path cannot contain ':', so split at the first one.
                val colon = inner.indexOf(':')
                val path = if (colon >= 0) inner.substring(0, colon) else inner
                if (!isValidPath(path)) return null
                var fmt: String? = null
                if (colon >= 0) {
                    val f = inner.substring(colon + 1)
                    if (f.isEmpty() || !f.all { it in 'a'..'z' }) return null
                    if (f !in formatters) return null
                    fmt = f
                }
                flush()
                out += Token.Placeholder(path.split("."), fmt)
                i = end + 1
                continue
            }
            if (c == '}') {
                if (i + 1 < text.length && text[i + 1] == '}') { lit.append('}'); i += 2; continue }
                return null
            }
            lit.append(c)
            i++
        }
        flush()
        return out
    }

    /** `^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*$` */
    internal fun isValidPath(p: String): Boolean {
        if (p.isEmpty()) return false
        var segLen = 0
        for (c in p) {
            if (c == '.') {
                if (segLen == 0) return false
                segLen = 0
            } else if (c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '_') {
                segLen++
            } else {
                return false
            }
        }
        return segLen > 0
    }

    internal fun lookup(args: JsonObject, path: List<String>): JsonValue? {
        var cur: JsonValue = JsonValue.Obj(args)
        for (seg in path) {
            cur = when (cur) {
                is JsonValue.Arr -> {
                    if (seg.isEmpty() || !seg.all { it in '0'..'9' }) return null
                    val idx = seg.toIntOrNull() ?: return null
                    if (idx >= cur.items.size) return null
                    cur.items[idx]
                }
                is JsonValue.Obj -> cur.obj[seg] ?: return null
                else -> return null
            }
        }
        return cur
    }

    /** §3.2 value rendering: strings verbatim, everything else as its JCS text. */
    fun renderValue(v: JsonValue): String {
        if (v is JsonValue.Str) return v.value
        return try {
            Jcs.canonicalize(v)
        } catch (_: JcsException) {
            ""
        }
    }

    // §3.5 links

    private fun isAlnum(c: Char) = c in '0'..'9' || c in 'A'..'Z' || c in 'a'..'z'
    private fun isHexDigit(c: Char) = c in '0'..'9' || c in 'A'..'F' || c in 'a'..'f'

    /** RFC 3986 unreserved: ALPHA DIGIT - . _ ~ */
    private fun isUnreserved(c: Char) = isAlnum(c) || c == '-' || c == '.' || c == '_' || c == '~'
    private const val URL_LITERAL_EXTRA = ":/?#@!$&'()*+,;="
    private const val UPPER_HEX = "0123456789ABCDEF"

    /** Literal URL characters outside placeholders: unreserved, `:/?#@!$&'()*+,;=`, and `%XX`. */
    internal fun isValidUrlLiteral(s: String): Boolean {
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (isUnreserved(c) || URL_LITERAL_EXTRA.indexOf(c) >= 0) { i++; continue }
            if (c == '%' && i + 2 < s.length && isHexDigit(s[i + 1]) && isHexDigit(s[i + 2])) { i += 3; continue }
            return false
        }
        return true
    }

    /** Lowercase LDH labels of 1–63, at least two labels, the last starting with a letter, at most 253 in all. */
    fun isValidLinkHost(h: String): Boolean {
        if (h.isEmpty() || h.length > 253) return false
        val labels = h.split(".")
        if (labels.size < 2) return false
        for (l in labels) {
            if (l.isEmpty() || l.length > 63) return false
            for ((i, c) in l.withIndex()) {
                val ok = c in '0'..'9' || c in 'a'..'z' || (c == '-' && i > 0 && i < l.length - 1)
                if (!ok) return false
            }
        }
        val last = labels.last()[0]
        return last in 'a'..'z'
    }

    /** Non-empty, at most 64 UTF-8 bytes, no control (C0, DEL, C1) or bidirectional formatting characters. */
    fun isValidLinkLabel(s: String): Boolean {
        if (s.isEmpty() || Chars.hasLoneSurrogate(s) || Utf8.length(s) > MAX_LINK_LABEL_BYTES) return false
        var i = 0
        while (i < s.length) {
            val c = s.codePointAt(i)
            if (c <= 0x1F || (c in 0x7F..0x9F) || c == 0x200E || c == 0x200F || (c in 0x202A..0x202E) || (c in 0x2066..0x2069)) return false
            i += Character.charCount(c)
        }
        return true
    }

    internal class ParsedLink(val label: String, val host: String, val tokens: List<Token>)

    internal fun parseLinkUrl(url: String, hosts: List<String>): Outcome<Pair<String, List<Token>>, LinksError> {
        if (url.length > MAX_LINK_URL_LENGTH) return Outcome.Err(LinksError.URL_INVALID)
        val tokens = tokenize(url, listOf("path")) ?: return Outcome.Err(LinksError.URL_INVALID)
        var fragments = 0
        for (t in tokens) {
            if (t is Token.Literal) {
                if (!isValidUrlLiteral(t.text)) return Outcome.Err(LinksError.URL_INVALID)
                fragments += t.text.count { it == '#' }
            }
        }
        if (fragments > 1) return Outcome.Err(LinksError.URL_INVALID)
        // Literals are ASCII from here on.
        val first = (tokens.firstOrNull() as? Token.Literal)?.text
        if (first == null || !first.startsWith("https://")) return Outcome.Err(LinksError.URL_NOT_HTTPS)
        val rest = first.substring(8)
        val slash = rest.indexOf('/')
        if (slash < 0) return Outcome.Err(LinksError.HOST_NOT_LITERAL)
        val host = rest.substring(0, slash)
        if (host !in hosts) return Outcome.Err(LinksError.HOST_NOT_ALLOWED)
        return Outcome.Ok(host to tokens)
    }

    internal fun parseLinks(t: Template): Outcome<List<ParsedLink>, LinksError> {
        val links = t.links ?: emptyList()
        val hosts = t.linkHosts ?: emptyList()
        if (links.size > MAX_LINKS) return Outcome.Err(LinksError.TOO_MANY_LINKS)
        if (hosts.size > MAX_LINK_HOSTS || !hosts.all(::isValidLinkHost) || (links.isNotEmpty() && hosts.isEmpty())) {
            return Outcome.Err(LinksError.LINK_HOSTS_INVALID)
        }
        val out = ArrayList<ParsedLink>()
        for (l in links) {
            if (!isValidLinkLabel(l.label)) return Outcome.Err(LinksError.LABEL_INVALID)
            when (val p = parseLinkUrl(l.url, hosts)) {
                is Outcome.Err -> return Outcome.Err(p.error)
                is Outcome.Ok -> out += ParsedLink(l.label, p.value.first, p.value.second)
            }
        }
        return Outcome.Ok(out)
    }

    /** §3.5 template-level link rules: null when the links (and hosts) are valid or absent. */
    fun linksError(t: Template): LinksError? = parseLinks(t).errorOrNull

    /** RFC 3986 percent-encoding of the UTF-8 bytes; unreserved characters stay, hex digits uppercase. */
    fun encodeLinkSegment(s: String): String {
        val out = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val v = b.toInt() and 0xFF
            if (v < 0x80 && isUnreserved(v.toChar())) out.append(v.toChar()) else out.append('%').append(UPPER_HEX[v shr 4]).append(UPPER_HEX[v and 0xF])
        }
        return out.toString()
    }

    /** One link for these args, or null when a value does not fit the rules (the link is dropped). */
    internal fun renderLink(l: ParsedLink, args: JsonObject): String? {
        val out = StringBuilder()
        for (tok in l.tokens) {
            when (tok) {
                is Token.Literal -> out.append(tok.text)
                is Token.Placeholder -> {
                    val v = lookup(args, tok.path) ?: return null
                    val s = when {
                        v is JsonValue.Str -> v.value
                        v is JsonValue.Num && v.intValue != null -> renderValue(v)
                        else -> return null
                    }
                    if (Chars.hasLoneSurrogate(s)) return null
                    // '/' is never half of a surrogate pair, so splitting UTF-16 at '/' splits by code point.
                    val segments = if (tok.fmt == "path") s.split("/") else listOf(s)
                    for (seg in segments) if (seg.isEmpty() || seg == "." || seg == "..") return null
                    out.append(segments.joinToString("/") { encodeLinkSegment(it) })
                }
            }
        }
        val url = out.toString()
        if (url.length > MAX_LINK_URL_LENGTH) return null
        val u = try {
            java.net.URI(url)
        } catch (_: Exception) {
            return null
        }
        if (u.scheme != "https" || u.host != l.host || u.rawUserInfo != null || u.port != -1) return null
        return url
    }

    /** §3.5: the review links for these args. Invalid links never fail the card; they are dropped with a code. */
    fun renderLinks(t: Template, args: JsonObject): Pair<List<RenderedLink>, LinksError?> =
        when (val p = parseLinks(t)) {
            is Outcome.Err -> emptyList<RenderedLink>() to p.error
            is Outcome.Ok -> p.value.mapNotNull { pl -> renderLink(pl, args)?.let { RenderedLink(pl.label, it, pl.host) } } to null
        }

    private class PathError(val path: String)

    /** Substitute values; `:short` takes the first 7 code points of a string. */
    private fun substitute(tokens: List<Token>, args: JsonObject): Outcome<String, PathError> {
        val out = StringBuilder()
        for (tok in tokens) {
            when (tok) {
                is Token.Literal -> out.append(tok.text)
                is Token.Placeholder -> {
                    val v = lookup(args, tok.path) ?: return Outcome.Err(PathError(tok.path.joinToString(".")))
                    if (tok.fmt == "short") {
                        val x = (v as? JsonValue.Str)?.value ?: return Outcome.Err(PathError(tok.path.joinToString(".")))
                        val cps = x.codePointCount(0, x.length)
                        out.append(if (cps <= SHORT_LENGTH) x else x.substring(0, x.offsetByCodePoints(0, SHORT_LENGTH)))
                    } else {
                        out.append(renderValue(v))
                    }
                }
            }
        }
        return Outcome.Ok(out.toString())
    }

    /**
     * §3.4 unreferenced-key rule, nested (mirrors `unreferenced` in `@signeto/protocol`): every leaf of
     * `args_resolved` (a scalar, or an empty object or array) must be under a `text` placeholder path, unless its
     * top-level key is elided. Objects in ECMAScript key order, arrays by index. Returns the first uncovered leaf as a
     * dotted path, and the elided top-level keys no placeholder names exactly.
     */
    internal fun unreferenced(args: JsonObject, refs: List<List<String>>, elide: Set<String>): Pair<String?, List<String>> {
        fun covered(path: List<String>): Boolean =
            refs.any { r -> r.size <= path.size && r.indices.all { r[it] == path[it] } }

        fun walk(v: JsonValue, path: List<String>): String? {
            if (covered(path)) return null
            return when {
                v is JsonValue.Arr && v.items.isNotEmpty() -> {
                    v.items.forEachIndexed { i, item -> walk(item, path + i.toString())?.let { return it } }
                    null
                }
                v is JsonValue.Obj && !v.obj.isEmpty() -> {
                    for (k in v.obj.ecmaScriptKeyOrder) walk(v.obj[k]!!, path + k)?.let { return it }
                    null
                }
                else -> path.joinToString(".")
            }
        }

        val hidden = ArrayList<String>()
        for (k in args.ecmaScriptKeyOrder) {
            if (covered(listOf(k))) continue
            if (k in elide) { hidden += k; continue }
            walk(args[k]!!, listOf(k))?.let { return it to hidden }
        }
        return null to hidden
    }

    /** Render the template line for canonical bytes. */
    fun render(canonicalBytes: String, registries: List<TemplateRegistry>): RenderResult =
        when (val p = CanonicalActions.parse(canonicalBytes)) {
            is Outcome.Err -> RenderResult.Unverified(UnverifiedReason.ACTION_MALFORMED, p.error.code, canonicalBytes)
            is Outcome.Ok -> render(p.value, registries)
        }

    fun render(parsed: EncodedAction, registries: List<TemplateRegistry>): RenderResult {
        val a = parsed.action
        val bytes = parsed.canonicalBytes
        val t = find(registries, a.templateId, a.templateVersion)
            ?: return RenderResult.Unverified(UnverifiedReason.UNKNOWN_TEMPLATE, null, bytes)
        if (!t.hashMatches) return RenderResult.Unverified(UnverifiedReason.TEMPLATE_HASH_MISMATCH, null, bytes)
        val hasNote = !t.note.isNullOrEmpty()
        val tokens = tokenize(t.text)
        val noteTokens = if (hasNote) tokenize(t.note!!, listOf("short")) else emptyList()
        if (tokens == null || noteTokens == null) return RenderResult.Unverified(UnverifiedReason.MALFORMED_TEMPLATE, null, bytes)
        val text = when (val r = substitute(tokens, a.argsResolved)) {
            is Outcome.Err -> return RenderResult.Unverified(UnverifiedReason.UNRESOLVED_PLACEHOLDER, r.error.path, bytes)
            is Outcome.Ok -> r.value
        }
        val note = when (val r = substitute(noteTokens, a.argsResolved)) {
            is Outcome.Err -> return RenderResult.Unverified(UnverifiedReason.UNRESOLVED_PLACEHOLDER, r.error.path, bytes)
            is Outcome.Ok -> r.value
        }
        // Only `text` placeholders count: the sentence must mention every argument (§3.4), not the note or a link.
        val refs = tokens.filterIsInstance<Token.Placeholder>().map { it.path }
        val (path, hidden) = unreferenced(a.argsResolved, refs, (t.elide ?: emptyList()).toSet())
        if (path != null) return RenderResult.Unverified(UnverifiedReason.UNREFERENCED_KEY, path, bytes)
        val (links, linksError) = renderLinks(t, a.argsResolved)
        // §3.6: the line and the note show control, bidi and invisible characters as escapes.
        return RenderResult.Ok(
            RenderedTemplate(Display.escape(text), t, hidden, if (hasNote) Display.escape(note) else null, links, linksError),
        )
    }
}
