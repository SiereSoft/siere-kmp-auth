package dev.siere.auth.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent

/** Credential-free Android sample. Consumer apps configure real providers in their own app module. */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SampleApp(listOf(demoProviderOption()))
        }
    }
}
