package dev.siere.auth.oidc

import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.readBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class EncryptedFileJvmOidcSessionStoreTest {
    @Test
    fun encryptedStoreRoundTripsWithoutWritingPlaintext() =
        runBlocking {
            val directory = Files.createTempDirectory("siere-oidc-store")
            val plaintext = "access-marker refresh-marker".encodeToByteArray()
            val store = EncryptedFileJvmOidcSessionStore(directory, "test")

            store.write(plaintext)

            assertContentEquals(plaintext, store.read())
            assertFalse(
                directory
                    .resolve("test.session")
                    .readBytes()
                    .decodeToString()
                    .contains("access-marker"),
            )
            assertFalse(directory.resolve("test.key").readBytes().contentEquals(plaintext))
            if (Files.getFileStore(directory).supportsFileAttributeView("posix")) {
                assertEquals(
                    setOf(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.OWNER_EXECUTE,
                    ),
                    Files.getPosixFilePermissions(directory),
                )
            }
        }

    @Test
    fun tamperedCiphertextIsRejectedAndCleared() =
        runBlocking {
            val directory = Files.createTempDirectory("siere-oidc-store")
            val store = EncryptedFileJvmOidcSessionStore(directory, "test")
            store.write("secret".encodeToByteArray())
            val path = directory.resolve("test.session")
            val damaged = path.readBytes().also { it[it.lastIndex] = (it.last() + 1).toByte() }
            Files.write(path, damaged)

            assertNull(store.read())
            assertFalse(Files.exists(path))
        }

    @Test
    fun differentWritesUseDifferentCiphertext() =
        runBlocking {
            val directory = Files.createTempDirectory("siere-oidc-store")
            val store = EncryptedFileJvmOidcSessionStore(directory, "test")
            store.write("same value".encodeToByteArray())
            val first = directory.resolve("test.session").readBytes()
            store.write("same value".encodeToByteArray())
            val second = directory.resolve("test.session").readBytes()

            assertFalse(first.contentEquals(second))
        }
}
