package bob.e2e.util

import org.springframework.core.io.ClassPathResource
import java.awt.image.BufferedImage
import java.io.File
import javax.imageio.ImageIO

object ImageUtil {
    fun mergeImages(imagePaths: List<String>, outputPath: String, rows: Int, columns: Int) {
        if (imagePaths.size != rows * columns) {
            throw IllegalArgumentException("not match")
        }

        val images = imagePaths.map { path ->
            val resource = ClassPathResource(path)
            if (resource.exists()) {
                resource.inputStream.use { ImageIO.read(it) }
            } else {
                throw IllegalArgumentException("not found: $path")
            }
        }

        val imageWidth = images[0].width
        val imageHeight = images[0].height

        val mergedImage = BufferedImage(imageWidth * columns, imageHeight * rows, BufferedImage.TYPE_INT_ARGB)

        val graphics = mergedImage.createGraphics()
        for (i in imagePaths.indices) {
            val x = (i % columns) * imageWidth
            val y = (i / columns) * imageHeight
            graphics.drawImage(images[i], x, y, null)
        }
        graphics.dispose()

        ImageIO.write(mergedImage, "PNG", File(outputPath))
    }
}