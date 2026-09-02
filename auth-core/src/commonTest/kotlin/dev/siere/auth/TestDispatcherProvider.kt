package dev.siere.auth

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlin.test.Test
import kotlin.test.assertSame

internal class TestDispatcherProvider(
    dispatcher: CoroutineDispatcher,
) : DispatcherProvider {
    override val main: CoroutineDispatcher = dispatcher
    override val default: CoroutineDispatcher = dispatcher
    override val io: CoroutineDispatcher = dispatcher
    override val unconfined: CoroutineDispatcher = dispatcher
}

class DispatcherProviderTest {
    @Test
    fun testProviderRoutesEveryLaneToTheInjectedDispatcher() {
        val dispatcher = StandardTestDispatcher(TestScope().testScheduler)
        val provider = TestDispatcherProvider(dispatcher)

        assertSame(dispatcher, provider.main)
        assertSame(dispatcher, provider.default)
        assertSame(dispatcher, provider.io)
        assertSame(dispatcher, provider.unconfined)
    }
}
