package dev.siere.auth

/**
 * The result of a fallible authentication operation: either a [Success] carrying a value
 * or a [Failure] carrying a typed [AuthError]. The library never throws across its API.
 */
public sealed class AuthResult<out T> {
    public data class Success<T>(
        val value: T,
    ) : AuthResult<T>()

    public data class Failure(
        val error: AuthError,
    ) : AuthResult<Nothing>()

    /** The value on success, `null` on failure. */
    public fun getOrNull(): T? = (this as? Success)?.value

    /** The error on failure, `null` on success. */
    public fun errorOrNull(): AuthError? = (this as? Failure)?.error

    public val isSuccess: Boolean get() = this is Success
}

/** Transforms the success value, passing failures through unchanged. */
public inline fun <T, R> AuthResult<T>.map(transform: (T) -> R): AuthResult<R> =
    when (this) {
        is AuthResult.Success -> AuthResult.Success(transform(value))
        is AuthResult.Failure -> this
    }

/** Runs [block] with the value when this is a [AuthResult.Success]; returns this unchanged. */
public inline fun <T> AuthResult<T>.onSuccess(block: (T) -> Unit): AuthResult<T> {
    if (this is AuthResult.Success) block(value)
    return this
}

/** Runs [block] with the error when this is a [AuthResult.Failure]; returns this unchanged. */
public inline fun <T> AuthResult<T>.onFailure(block: (AuthError) -> Unit): AuthResult<T> {
    if (this is AuthResult.Failure) block(error)
    return this
}
