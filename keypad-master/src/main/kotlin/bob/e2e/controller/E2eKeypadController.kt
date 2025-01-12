package bob.e2e.controller

import bob.e2e.service.KeypadService
import org.springframework.boot.autoconfigure.web.client.RestTemplateAutoConfiguration
import org.springframework.http.*
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.RestTemplate
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Base64

@RestController
@RequestMapping("/api")
class E2eKeypadController(
    private val keypadService: KeypadService,
    private val restTemplate: RestTemplate
) {
    @GetMapping("/keypad")
    fun getKeypad(): ResponseEntity<Map<String, Any>> {
        val keypads = keypadService.getAllKeypads()
        keypads.forEach { keypad ->
            println("ID: ${keypad.id}, Hash: ${keypad.hash}")
        }

        val imageBytes = keypads.firstOrNull()?.image

        return if (imageBytes != null) {
            val imageBase64 = Base64.getEncoder().encodeToString(imageBytes)
            val hashes = keypads.map { it.hash }
            val response = mapOf("image" to imageBase64, "hashes" to hashes)
            ResponseEntity.ok(response)
        } else {
            ResponseEntity.status(HttpStatus.NOT_FOUND).build()
        }
    }
    @PostMapping("/submit")
    fun receiveEncryptedData(@RequestBody requestBody: Map<String, String>): ResponseEntity<String> {
        val encryptedData = requestBody["encryptedData"]

        return if (encryptedData != null) {
            println("Received encrypted data: $encryptedData")
            ResponseEntity.ok("Data received successfully")
        } else {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Encrypted data is missing")
        }
    }
//    @PostMapping("/submit")
//    fun receiveEncryptedData(@RequestBody requestBody: Map<String, String>): ResponseEntity<String> {
//        val encryptedData = requestBody["encryptedData"]
//        val timestamp = requestBody["timestamp"]
//
//        if (encryptedData != null && timestamp != null) {
//            println("Received encrypted data: $encryptedData")
//            val requestTime: Long = try {
//                timestamp.toLong()
//            } catch (e: NumberFormatException) {
//                println("Invalid timestamp format: $timestamp")
//                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid timestamp format")
//            }
//            val now = Instant.now()
//            val timeDifference = ChronoUnit.MINUTES.between(Instant.ofEpochSecond(requestTime), now)
//
//            if (timeDifference > 5) {
//                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Timestamp is expired")
//            }
//
//            println("Timestamp is valid, time difference: $timeDifference minutes")
//            val response = sendToAuthEndpoint(encryptedData)
//            return ResponseEntity.ok(response)
//        } else {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Encrypted data or timestamp is missing")
//        }
//    }
//
//
//
//
//    private fun sendToAuthEndpoint(encryptedData: String): String {
//        val url = "http://146.56.119.112:8081/auth"
//
//        val headers = HttpHeaders().apply {
//            contentType = org.springframework.http.MediaType.APPLICATION_JSON
//        }
//        val body = mapOf(
//            "userInput" to encryptedData,
//            "keyHashMap" to mapOf<String, String>() // 필요에 따라 적절한 키-값 쌍을 넣으세요.
//        )
//        val requestEntity = HttpEntity(body, headers)
//
//        val responseEntity: ResponseEntity<String> = restTemplate.exchange(
//            url, HttpMethod.POST, requestEntity, String::class.java
//        )
//        println("Received response from $url")
//        println("Response status: ${responseEntity.statusCode}")
//        println("Response body: ${responseEntity.body}")
//        return responseEntity.body ?: "No response body"
//    }
}
