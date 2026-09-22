import dev.siere.auth.oidc.OidcSessionStore
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringCreateWithCString
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFStringEncodingUTF8
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData

/** Stores the opaque serialized OIDC session in the application Keychain. */
class IosKeychainOidcSessionStore internal constructor(
    private val service: String,
    private val account: String,
    private val keychain: IosKeychainClient,
) : OidcSessionStore {
    constructor(
        service: String,
        account: String,
    ) : this(service, account, AppleIosKeychainClient)

    override suspend fun read(): ByteArray? = keychain.read(service, account)

    override suspend fun write(value: ByteArray) {
        keychain.write(service, account, value)
    }

    override suspend fun clear() {
        keychain.clear(service, account)
    }
}

internal interface IosKeychainClient {
    fun read(
        service: String,
        account: String,
    ): ByteArray?

    fun write(
        service: String,
        account: String,
        value: ByteArray,
    )

    fun clear(
        service: String,
        account: String,
    )
}

@OptIn(ExperimentalForeignApi::class)
private object AppleIosKeychainClient : IosKeychainClient {
    override fun read(
        service: String,
        account: String,
    ): ByteArray? {
        val query = baseQuery(service, account)
        CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue)
        CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne)
        return try {
            memScoped {
                val result = alloc<CFTypeRefVar>()
                when (val status = SecItemCopyMatching(query, result.ptr)) {
                    errSecSuccess -> {
                        val data = checkNotNull(result.value).reinterpret<cnames.structs.__CFData>()
                        try {
                            val length = CFDataGetLength(data).toInt()
                            CFDataGetBytePtr(data)?.readBytes(length) ?: ByteArray(0)
                        } finally {
                            CFRelease(data)
                        }
                    }
                    errSecItemNotFound -> null
                    else -> keychainFailure("read", status)
                }
            }
        } finally {
            CFRelease(query)
        }
    }

    override fun write(
        service: String,
        account: String,
        value: ByteArray,
    ) {
        val data =
            value.usePinned { pinned ->
                CFDataCreate(
                    allocator = kCFAllocatorDefault,
                    bytes = if (value.isEmpty()) null else pinned.addressOf(0).reinterpret(),
                    length = value.size.toLong(),
                ) ?: error("Could not allocate Keychain session data")
            }
        try {
            val query = baseQuery(service, account)
            val update = mutableDictionary()
            CFDictionarySetValue(update, kSecValueData, data)
            try {
                when (val status = SecItemUpdate(query, update)) {
                    errSecSuccess -> Unit
                    errSecItemNotFound -> add(service, account, valueData = data)
                    else -> keychainFailure("update", status)
                }
            } finally {
                CFRelease(update)
                CFRelease(query)
            }
        } finally {
            CFRelease(data)
        }
    }

    override fun clear(
        service: String,
        account: String,
    ) {
        val query = baseQuery(service, account)
        try {
            when (val status = SecItemDelete(query)) {
                errSecSuccess, errSecItemNotFound -> Unit
                else -> keychainFailure("delete", status)
            }
        } finally {
            CFRelease(query)
        }
    }

    private fun add(
        service: String,
        account: String,
        valueData: kotlinx.cinterop.CPointer<cnames.structs.__CFData>,
    ) {
        val attributes = baseQuery(service, account)
        try {
            CFDictionarySetValue(attributes, kSecAttrAccessible, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
            CFDictionarySetValue(attributes, kSecValueData, valueData)
            val status = SecItemAdd(attributes, null)
            if (status != errSecSuccess) keychainFailure("add", status)
        } finally {
            CFRelease(attributes)
        }
    }

    private fun baseQuery(
        service: String,
        account: String,
    ) = mutableDictionary().also { query ->
        val serviceValue = cfString(service)
        val accountValue = cfString(account)
        try {
            CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword)
            CFDictionarySetValue(query, kSecAttrService, serviceValue)
            CFDictionarySetValue(query, kSecAttrAccount, accountValue)
        } finally {
            CFRelease(serviceValue)
            CFRelease(accountValue)
        }
    }

    private fun cfString(value: String) =
        checkNotNull(
            CFStringCreateWithCString(kCFAllocatorDefault, value, kCFStringEncodingUTF8),
        )

    private fun mutableDictionary() =
        checkNotNull(
            CFDictionaryCreateMutable(
                allocator = kCFAllocatorDefault,
                capacity = 0,
                keyCallBacks = kCFTypeDictionaryKeyCallBacks.ptr,
                valueCallBacks = kCFTypeDictionaryValueCallBacks.ptr,
            ),
        )

    private fun keychainFailure(
        operation: String,
        status: Int,
    ): Nothing = error("Could not $operation the OIDC Keychain session (OSStatus $status)")
}
