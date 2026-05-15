package kz.ncanode.service

import kz.ncanode.configuration.SystemConfiguration
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import java.io.File
import java.nio.file.Paths

@Service
class DirectoryService(private val systemConfiguration: SystemConfiguration) {

    /**
     * Возвращает путь к кэшу или `null`, если каталог нельзя создать.
     */
    fun getCachePathFor(dirName: String): File? {
        val file = Paths.get(systemConfiguration.cacheDir, dirName).normalize().toAbsolutePath().toFile()
        if ((!file.exists() || !file.isDirectory) && !file.mkdirs()) {
            log.error("Cannot get cache path for: {}", file)
            return null
        }
        return file
    }

    companion object {
        private val log = LoggerFactory.getLogger(DirectoryService::class.java)
    }
}
