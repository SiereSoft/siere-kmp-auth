package dev.siere.auth.oidc

import java.net.URI
import kotlin.test.Test
import kotlin.test.assertFailsWith

class OidcHttpTest {
    @Test
    fun insecureTestHttpAcceptsOnlyNumericLoopbackHosts() {
        URI("http://127.0.0.1:8080/discovery").requireSecure(true, "discoveryUrl")
        URI("http://[::1]:8080/discovery").requireSecure(true, "discoveryUrl")

        assertFailsWith<IllegalArgumentException> {
            URI("http://localhost:8080/discovery").requireSecure(true, "discoveryUrl")
        }
        assertFailsWith<IllegalArgumentException> {
            URI("http://127.0.0.1.example/discovery").requireSecure(true, "discoveryUrl")
        }
    }
}
