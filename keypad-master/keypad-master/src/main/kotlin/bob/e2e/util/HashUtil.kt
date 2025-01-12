package bob.e2e.util

import java.security.MessageDigest
import kotlin.random.Random

object HashUtil {
    fun sha1(input: String): String {
        val md = MessageDigest.getInstance("SHA-1")
        return md.digest(input.toByteArray()).joinToString("") { "%02x".format(it) }
    }

    fun generateHash(base: String): String {
        val randomSuffix = Random.nextLong().toString()
        return sha1(base + randomSuffix)
    }
}