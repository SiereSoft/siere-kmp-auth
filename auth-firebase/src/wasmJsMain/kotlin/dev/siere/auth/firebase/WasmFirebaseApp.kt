@file:JsModule("firebase/app")
@file:OptIn(kotlin.js.ExperimentalWasmJsInterop::class)
@file:Suppress("ktlint:standard:filename")

package dev.siere.auth.firebase

internal external interface FirebaseApp : JsAny

internal external fun initializeApp(options: JsAny): FirebaseApp
