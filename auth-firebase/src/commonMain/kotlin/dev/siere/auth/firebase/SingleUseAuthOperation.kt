package dev.siere.auth.firebase

import dev.siere.auth.AuthResult
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Serializes competing platform completions and keeps the first terminal auth result. */
internal class SingleUseAuthOperation<T> {
    private val mutex = Mutex()
    private var terminal: AuthResult<T>? = null

    suspend fun complete(operation: suspend () -> AuthResult<T>): AuthResult<T> =
        mutex.withLock {
            terminal ?: operation().also { terminal = it }
        }

    suspend fun fail(failure: AuthResult.Failure): Unit =
        mutex.withLock {
            if (terminal == null) terminal = failure
        }
}
