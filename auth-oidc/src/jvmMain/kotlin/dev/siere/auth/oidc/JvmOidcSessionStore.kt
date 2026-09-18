@file:Suppress("MagicNumber")

package dev.siere.auth.oidc

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Persistence boundary for sensitive OIDC session data. Implementations must protect it at rest. */
public interface JvmOidcSessionStore : OidcSessionStore {
    override suspend fun read(): ByteArray?

    override suspend fun write(value: ByteArray)

    override suspend fun clear()
}

/**
 * File-backed session storage for desktop JVM applications.
 *
 * Session contents are encrypted with AES-256-GCM. The random key and ciphertext are separate,
 * owner-only files where POSIX permissions are supported. This prevents plaintext disclosure and
 * access by other OS users, but it is not an OS credential vault and cannot protect against code
 * already running as the same user. Applications with keychain access should provide their own
 * [JvmOidcSessionStore].
 */
public class EncryptedFileJvmOidcSessionStore(
    directory: Path,
    storageName: String = "siere-auth-oidc",
) : JvmOidcSessionStore {
    private val random = SecureRandom()
    private val keyPath = directory.resolve("$storageName.key")
    private val sessionPath = directory.resolve("$storageName.session")

    init {
        require(storageName.matches(Regex("[A-Za-z0-9._-]+"))) {
            "storageName may contain only letters, numbers, dot, underscore, and hyphen"
        }
    }

    override suspend fun read(): ByteArray? {
        if (!Files.isRegularFile(keyPath) || !Files.isRegularFile(sessionPath)) return null
        return runCatching {
            val key = Files.readAllBytes(keyPath)
            require(key.size == KEY_BYTES)
            val envelope = Files.readAllBytes(sessionPath)
            require(envelope.size > NONCE_BYTES)
            decrypt(key, envelope)
        }.getOrElse {
            clear()
            null
        }
    }

    override suspend fun write(value: ByteArray) {
        Files.createDirectories(keyPath.parent)
        setOwnerOnlyDirectoryPermissions(keyPath.parent)
        val key = loadOrCreateKey()
        atomicWrite(sessionPath, encrypt(key, value))
    }

    override suspend fun clear() {
        Files.deleteIfExists(sessionPath)
    }

    private fun loadOrCreateKey(): ByteArray {
        if (Files.isRegularFile(keyPath)) {
            return Files.readAllBytes(keyPath).also { require(it.size == KEY_BYTES) }
        }
        val key = ByteArray(KEY_BYTES).also(random::nextBytes)
        atomicWrite(keyPath, key)
        setOwnerOnlyPermissions(keyPath)
        return key
    }

    private fun encrypt(
        key: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        return nonce + cipher.doFinal(plaintext)
    }

    private fun decrypt(
        key: ByteArray,
        envelope: ByteArray,
    ): ByteArray {
        val nonce = envelope.copyOfRange(0, NONCE_BYTES)
        val ciphertext = envelope.copyOfRange(NONCE_BYTES, envelope.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, nonce))
        return cipher.doFinal(ciphertext)
    }

    private fun atomicWrite(
        path: Path,
        value: ByteArray,
    ) {
        val temporary = Files.createTempFile(path.parent, ".${path.fileName}.", ".tmp")
        try {
            Files.write(temporary, value)
            setOwnerOnlyPermissions(temporary)
            runCatching {
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            }.getOrElse {
                Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
            }
            setOwnerOnlyPermissions(path)
        } finally {
            Files.deleteIfExists(temporary)
        }
    }

    private fun setOwnerOnlyPermissions(path: Path) {
        runCatching {
            Files.setPosixFilePermissions(
                path,
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
            )
        }
    }

    private fun setOwnerOnlyDirectoryPermissions(path: Path) {
        runCatching {
            Files.setPosixFilePermissions(
                path,
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE,
                ),
            )
        }
    }
}

private const val KEY_BYTES = 32
private const val NONCE_BYTES = 12
private const val TAG_BITS = 128
