package dev.siere.auth

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

public actual class DefaultDispatcherProvider actual constructor() : DispatcherProvider {
    // Core JVM has no UI runtime dependency, so Main safely maps to the general scheduler.
    public actual override val main: CoroutineDispatcher = Dispatchers.Default
    public actual override val default: CoroutineDispatcher = Dispatchers.Default
    public actual override val io: CoroutineDispatcher = Dispatchers.IO
    public actual override val unconfined: CoroutineDispatcher = Dispatchers.Unconfined
}
