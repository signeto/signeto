package dev.signeto.sign

import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test

/**
 * Shared vectors `vectors/handoff/` (protocol.md §5.6): the device-side handoff check, case for case with
 * `verifyHandoffForDevice` in @signeto/protocol.
 */
class HandoffTests {
    private fun pin(v: JsonValue): HandoffGatewayPin {
        val pins = (v["templates_pinned"]?.arrayValue ?: emptyList()).map { TemplatePin(it("template_id").s, it("template_version").intValue!!, it("sha256").s) }
        return HandoffGatewayPin(v("gateway_id").s, v("public_key").jwk()!!, v("approver_id").s, pins)
    }

    private fun move(): JsonValue = loadJson(File(Paths.vectors, "handoff/move.json"))

    @Test
    fun deviceCases() {
        val cases = loadJson(File(Paths.vectors, "handoff/device-cases.json"))("cases").arrayValue!!
        assertEquals(23, cases.size)
        for (c in cases) {
            val name = c("name").s
            val i = c("inputs")
            val e = c("expected")
            val r = Handoff.verifyForDevice(HandoffRequest.fromJson(i("handoff"))!!, pin(i("pin")), i("device_public_key").jwk()!!, i("receipt"), i["completion"])
            if (e["ok"]?.boolValue == true) {
                val v = r.valueOrNull ?: fail("$name: ${r.errorOrNull}")
                assertEquals(e("completed").boolValue, v.completed, name)
                assertEquals(e("late").boolValue, v.late, name)
            } else {
                assertEquals(e("error").s, r.errorOrNull?.code, name)
            }
        }
    }

    @Test
    fun moveVectorSuccessorPin() {
        val m = move()
        val i = m("inputs")
        val e = m("expected")
        val r = Handoff.verifyForDevice(HandoffRequest.fromJson(e("handoff"))!!, pin(i("pin")), i("device_private_key").publicHalf()!!, e("receipt"), e("completion"))
        val v = r.valueOrNull ?: fail("${r.errorOrNull}")
        val want = e("successor_pin")
        assertEquals(SuccessorPin(want("gateway_id").s, want("public_key").jwk()!!, want("name").s, want("approver_id").s, pin(want).templatesPinned, want("predecessor_gateway_id").s), v.successor)
        assertTrue(v.completed)
        assertFalse(v.late)
        assertEquals(e("canonical_bytes").s, v.action.canonicalBytes)
    }

    @Test
    fun completionSigningInput() {
        val e = move()("expected")
        val input = Handoff.completionSigningInput(e("completion").objectValue!!)
        assertEquals(e("completion_signing_input").s, input)
        assertTrue(input.contains("\"purpose\":\"gateway.handoff.complete\""))
    }

    @Test
    fun bundledTemplateRenders() {
        val e = move()("expected")
        val r = Templates.render(e("canonical_bytes").s, Templates.builtinRegistries).renderedOrNull ?: fail("handoff template did not verify")
        assertEquals(e("rendered")("text").s, r.text)
        assertEquals(e("rendered")("note").s, r.note)
        assertEquals(e("rendered")("hidden").arrayValue!!.map { it.s }, r.hidden)
        assertEquals(Handoff.TOOL, r.template.templateId)
    }

    @Test
    fun successorNameRule() {
        assertTrue(Handoff.isValidSuccessorName("Signeto Cloud"))
        for (bad in listOf("", " padded", "padded ", "a‮b", "x".repeat(65))) assertFalse(Handoff.isValidSuccessorName(bad), bad)
    }
}
