package dev.siere.auth.firebase

internal class FirebaseAuthStateChangedException : IllegalStateException("The signed-in account changed")

internal suspend inline fun <T> withExpectedUser(
    expectedUid: String,
    crossinline currentUid: () -> String?,
    crossinline operation: suspend () -> T,
): T {
    if (currentUid() != expectedUid) throw FirebaseAuthStateChangedException()
    val result = operation()
    if (currentUid() != expectedUid) throw FirebaseAuthStateChangedException()
    return result
}
