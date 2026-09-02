package dev.siere.auth

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers

public actual class DefaultDispatcherProvider actual constructor() : DispatcherProvider {
    // Wasm/JS shares the browser event loop and does not provide a separate IO pool.
    public actual override val main: CoroutineDispatcher = Dispatchers.Default
    public actual override val default: CoroutineDispatcher = Dispatchers.Default
    public actual override val io: CoroutineDispatcher = Dispatchers.Default
    public actual override val unconfined: CoroutineDispatcher = Dispatchers.Unconfined
}
