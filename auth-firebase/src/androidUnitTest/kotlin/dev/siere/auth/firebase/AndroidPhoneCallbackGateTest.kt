package dev.siere.auth.firebase

import kotlin.test.Test
import kotlin.test.assertFalse

class AndroidPhoneCallbackGateTest {
    @Test
    fun invalidatedGateRejectsLateAutomaticVerification() {
        val gate = AndroidPhoneCallbackGate()
        var completed = false

        gate.invalidate()
        val accepted = gate.runIfActive { completed = true }

        assertFalse(accepted)
        assertFalse(completed)
    }
}
