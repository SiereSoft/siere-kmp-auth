package dev.siere.auth.sample

import android.app.Application
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import com.google.firebase.FirebasePlatform
import dev.gitlive.firebase.Firebase
import dev.gitlive.firebase.FirebaseOptions
import dev.gitlive.firebase.initialize
import dev.siere.auth.firebase.FirebaseAuthProvider
import dev.siere.auth.firebase.JvmGoogleAuthConfig
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Properties

private const val FIREBASE_API_KEY = "SIERE_SAMPLE_FIREBASE_API_KEY"
private const val FIREBASE_APP_ID = "SIERE_SAMPLE_FIREBASE_APP_ID"
private const val FIREBASE_PROJECT_ID = "SIERE_SAMPLE_FIREBASE_PROJECT_ID"
private const val GOOGLE_CLIENT_ID = "SIERE_SAMPLE_GOOGLE_CLIENT_ID"
private const val GOOGLE_CLIENT_SECRET = "SIERE_SAMPLE_GOOGLE_CLIENT_SECRET"
private const val STORAGE_DIRECTORY = "SIERE_SAMPLE_STORAGE_DIRECTORY"

/** Runs the credential-free Desktop sample, enabling Firebase only from consumer-owned environment values. */
public fun main() {
    val options = desktopProviderOptions(System.getenv())
    application {
        Window(onCloseRequest = ::exitApplication, title = "Siere KMP Auth") {
            SampleApp(options)
        }
    }
}

internal fun desktopProviderOptions(environment: Map<String, String>): List<ProviderOption> {
    val options = mutableListOf(ProviderOption("Demo") { DemoAuthProvider() })
    val config = DesktopFirebaseConfig.from(environment) ?: return options
    val storageDirectory =
        environment.nonBlank(STORAGE_DIRECTORY)?.let(::File)
            ?: File(System.getProperty("java.io.tmpdir"), "siere-kmp-auth-desktop-sample")

    FirebasePlatform.initializeFirebasePlatform(FileBackedFirebasePlatform(storageDirectory))
    Firebase.initialize(
        Application(),
        FirebaseOptions(
            applicationId = config.applicationId,
            apiKey = config.apiKey,
            projectId = config.projectId,
        ),
    )
    options +=
        ProviderOption(
            name = "Firebase",
            backendOrigin = "https://${config.projectId}.firebaseapp.com",
        ) {
            FirebaseAuthProvider(
                JvmGoogleAuthConfig(
                    clientId = config.googleClientId,
                    clientSecret = environment.nonBlank(GOOGLE_CLIENT_SECRET),
                ),
            )
        }
    return options
}

internal data class DesktopFirebaseConfig(
    val apiKey: String,
    val applicationId: String,
    val projectId: String,
    val googleClientId: String,
) {
    companion object {
        fun from(environment: Map<String, String>): DesktopFirebaseConfig? =
            environment
                .takeIf { values ->
                    listOf(FIREBASE_API_KEY, FIREBASE_APP_ID, FIREBASE_PROJECT_ID, GOOGLE_CLIENT_ID)
                        .all { name -> values.nonBlank(name) != null }
                }?.let { values ->
                    DesktopFirebaseConfig(
                        apiKey = checkNotNull(values.nonBlank(FIREBASE_API_KEY)),
                        applicationId = checkNotNull(values.nonBlank(FIREBASE_APP_ID)),
                        projectId = checkNotNull(values.nonBlank(FIREBASE_PROJECT_ID)),
                        googleClientId = checkNotNull(values.nonBlank(GOOGLE_CLIENT_ID)),
                    )
                }
    }
}

private fun Map<String, String>.nonBlank(name: String): String? = get(name)?.takeIf(String::isNotBlank)

/**
 * Minimal durable storage for exercising restart restoration in the sample.
 * Production applications should replace this with OS credential storage.
 */
internal class FileBackedFirebasePlatform(
    private val directory: File,
) : FirebasePlatform() {
    private val lock = Any()

    override fun store(
        key: String,
        value: String,
    ) {
        synchronized(lock) {
            check(directory.isDirectory || directory.mkdirs()) {
                "Could not create the Desktop sample session directory"
            }
            val destination = fileFor(key)
            val temporary = File(directory, "${destination.name}.tmp")
            Properties().apply { setProperty("value", value) }.run {
                temporary.outputStream().use { store(it, null) }
            }
            try {
                Files.move(
                    temporary.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE,
                )
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(
                    temporary.toPath(),
                    destination.toPath(),
                    StandardCopyOption.REPLACE_EXISTING,
                )
            }
        }
    }

    override fun retrieve(key: String): String? =
        synchronized(lock) {
            fileFor(key)
                .takeIf(File::isFile)
                ?.inputStream()
                ?.use { Properties().apply { load(it) }.getProperty("value") }
        }

    override fun clear(key: String) {
        synchronized(lock) {
            Files.deleteIfExists(fileFor(key).toPath())
        }
    }

    override fun log(msg: String): Unit = Unit

    override fun getDatabasePath(name: String): File = File(directory, "database-${safeName(name)}")

    private fun fileFor(key: String): File = File(directory, "auth-${safeName(key)}.properties")

    private fun safeName(value: String): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(value.toByteArray(StandardCharsets.UTF_8))
            .joinToString(separator = "") { byte -> "%02x".format(byte) }
}
