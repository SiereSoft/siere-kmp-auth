package dev.siere.auth

import kotlinx.coroutines.CoroutineDispatcher

/**
 * Platform-aware coroutine dispatchers used by auth implementations.
 *
 * Inject a custom implementation when integrating with an application scheduler or when using
 * virtual time in tests. The default implementation selects dispatchers appropriate to each
 * supported Kotlin target.
 */
public interface DispatcherProvider {
    public val main: CoroutineDispatcher
    public val default: CoroutineDispatcher
    public val io: CoroutineDispatcher
    public val unconfined: CoroutineDispatcher
}

/** Returns the platform's default auth dispatchers. */
public expect class DefaultDispatcherProvider() : DispatcherProvider {
    override val main: CoroutineDispatcher
    override val default: CoroutineDispatcher
    override val io: CoroutineDispatcher
    override val unconfined: CoroutineDispatcher
}
