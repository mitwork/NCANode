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

    /**
     * Удаляет из каталога [dirName] файлы с расширением [extension], чей stem
     * (имя без расширения) не входит в [validKeys] — orphan'ы от прошлых
     * конфигов. [label] — слово для логов ("CRL" / "CA"). Раньше эта логика
     * дублировалась в CrlService и CaService.
     */
    fun deleteOrphans(dirName: String, extension: String, validKeys: Set<String>, label: String) {
        val cacheDir = getCachePathFor(dirName) ?: return
        val files = cacheDir.listFiles() ?: return
        for (f in files) {
            if (!f.isFile || !f.name.endsWith(extension)) continue
            val stem = f.name.substring(0, f.name.length - extension.length)
            if (stem !in validKeys) {
                if (f.delete()) {
                    log.info("Deleted orphan {} cache file: {}", label, f.name)
                } else {
                    log.warn("Could not delete orphan {} cache file: {}", label, f)
                }
            }
        }
    }

    companion object {
        private val log = LoggerFactory.getLogger(DirectoryService::class.java)
    }
}
