package dev.siere.auth.sample

import dev.siere.auth.AuthError
import dev.siere.auth.AuthResult
import dev.siere.auth.AuthSession
import kotlinx.io.IOException

/** Result displayed by the sample's credentialed backend call. */
sealed interface AuthenticatedCallResult {
    data class Success(
        val message: String,
    ) : AuthenticatedCallResult

    data class AuthFailure(
        val error: AuthError,
    ) : AuthenticatedCallResult

    data class HttpFailure(
        val statusCode: Int,
    ) : AuthenticatedCallResult

    data class NetworkFailure(
        val message: String,
    ) : AuthenticatedCallResult
}

internal data class SampleBackendResponse(
    val statusCode: Int,
    val successMessage: String,
)

/**
 * Obtains a point-in-time session immediately before a backend call. When the first request uses a
 * cached session and receives 401, it forces one refresh and retries exactly once.
 */
internal suspend fun authenticatedBackendCall(
    forceRefreshBeforeCall: Boolean = false,
    currentSession: suspend (forceRefresh: Boolean) -> AuthResult<AuthSession>,
    request: suspend (accessToken: String) -> SampleBackendResponse,
): AuthenticatedCallResult =
    when (val initial = currentSession(forceRefreshBeforeCall)) {
        is AuthResult.Failure -> AuthenticatedCallResult.AuthFailure(initial.error)
        is AuthResult.Success -> {
            val first = executeBackendRequest(initial.value.accessToken, request)
            val shouldRetry =
                !forceRefreshBeforeCall &&
                    first is AuthenticatedCallResult.HttpFailure &&
                    first.statusCode == HTTP_UNAUTHORIZED
            if (shouldRetry) {
                when (val refreshed = currentSession(true)) {
                    is AuthResult.Failure -> AuthenticatedCallResult.AuthFailure(refreshed.error)
                    is AuthResult.Success -> executeBackendRequest(refreshed.value.accessToken, request)
                }
            } else {
                first
            }
        }
    }

private suspend fun executeBackendRequest(
    accessToken: String,
    request: suspend (String) -> SampleBackendResponse,
): AuthenticatedCallResult =
    try {
        val response = request(accessToken)
        if (response.statusCode in HTTP_SUCCESS_MIN..HTTP_SUCCESS_MAX) {
            AuthenticatedCallResult.Success(response.successMessage)
        } else {
            AuthenticatedCallResult.HttpFailure(response.statusCode)
        }
    } catch (failure: IOException) {
        AuthenticatedCallResult.NetworkFailure(failure.message ?: "The protected request failed")
    }

private const val HTTP_SUCCESS_MIN = 200
private const val HTTP_SUCCESS_MAX = 299
private const val HTTP_UNAUTHORIZED = 401
