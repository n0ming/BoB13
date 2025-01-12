package bob.e2e.service

import bob.e2e.data.Keypad
import bob.e2e.util.HashUtil
import bob.e2e.util.ImageUtil
import org.springframework.stereotype.Service
import java.io.File
import kotlin.random.Random

@Service
class KeypadService {

    fun getAllKeypads(): List<Keypad> {
        val resourcesPath = "keypad/"
        val mergedImagePath = "merged_image.png"

        val keypadIds = (0..9).map { "_${it}.png" } + List(2) { "_blank.png" }

        val shuffledIds = keypadIds.shuffled(Random(System.currentTimeMillis()))
        val imagePaths = shuffledIds.map { "$resourcesPath$it" }
        val shuffledHashes = shuffledIds.map { HashUtil.generateHash(it) }

        println("Shuffled image paths: $imagePaths")
        println("Shuffled hashes: $shuffledHashes")

        if (imagePaths.size != 12) {
            println("Error, ${imagePaths.size}.")
            return emptyList()
        }

        ImageUtil.mergeImages(imagePaths, mergedImagePath, rows = 3, columns = 4)
        println("Merged successfully")

        val file = File(mergedImagePath)
        if (!file.exists()) {
            println("Merged image does not exist")
            return emptyList()
        }
        val imageBytes = file.readBytes()

        return shuffledHashes.mapIndexed { index, hash ->
            Keypad(index.toLong(), hash, imageBytes)
        }
    }
}
