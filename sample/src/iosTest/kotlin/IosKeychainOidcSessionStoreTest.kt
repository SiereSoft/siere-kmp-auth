import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNull

class IosKeychainOidcSessionStoreTest {
    @Test
    fun sessionSurvivesAStoreRecreationAndCanBeRemoved() =
        runTest {
            val keychain = InMemoryIosKeychainClient()
            val first = IosKeychainOidcSessionStore(TEST_SERVICE, TEST_ACCOUNT, keychain)
            val second = IosKeychainOidcSessionStore(TEST_SERVICE, TEST_ACCOUNT, keychain)
            val original = byteArrayOf(0, 1, 2, 127, -1)
            val replacement = byteArrayOf(9, 8, 7)

            first.clear()
            try {
                first.write(original)
                assertContentEquals(original, second.read())

                second.write(replacement)
                assertContentEquals(replacement, first.read())

                second.clear()
                assertNull(first.read())
            } finally {
                first.clear()
            }
        }

    private companion object {
        const val TEST_SERVICE = "dev.siere.auth.sample.oidc.tests"
        const val TEST_ACCOUNT = "test-account"
    }
}

private class InMemoryIosKeychainClient : IosKeychainClient {
    private val values = mutableMapOf<Pair<String, String>, ByteArray>()

    override fun read(
        service: String,
        account: String,
    ): ByteArray? = values[service to account]?.copyOf()

    override fun write(
        service: String,
        account: String,
        value: ByteArray,
    ) {
        values[service to account] = value.copyOf()
    }

    override fun clear(
        service: String,
        account: String,
    ) {
        values.remove(service to account)
    }
}
