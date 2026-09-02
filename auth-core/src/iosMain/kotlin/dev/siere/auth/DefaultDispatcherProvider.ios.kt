package dev.siere.auth

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO

public actual class DefaultDispatcherProvider actual constructor() : DispatcherProvider {
    public actual override val main: CoroutineDispatcher = Dispatchers.Main
    public actual override val default: CoroutineDispatcher = Dispatchers.Default
    public actual override val io: CoroutineDispatcher = Dispatchers.IO
    public actual override val unconfined: CoroutineDispatcher = Dispatchers.Unconfined
}
