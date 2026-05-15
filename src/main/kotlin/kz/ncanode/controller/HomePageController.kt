package kz.ncanode.controller

import io.swagger.v3.oas.annotations.Hidden
import kz.ncanode.NCANode
import kz.ncanode.service.MaintenanceService
import org.springframework.beans.factory.annotation.Value
import org.springframework.core.io.Resource
import org.springframework.http.MediaType
import org.springframework.stereotype.Controller
import org.springframework.util.FileCopyUtils
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseBody
import java.io.IOException
import java.io.InputStreamReader
import java.io.UncheckedIOException
import java.nio.charset.StandardCharsets

@Controller
@Hidden
class HomePageController(private val maintenanceService: MaintenanceService) {

    @Value("classpath:home.html")
    private lateinit var homePage: Resource

    @RequestMapping(value = ["/"], produces = [MediaType.TEXT_HTML_VALUE])
    @ResponseBody
    fun homePage(): String = loadHtml()
        .replace(variable("VERSION"), maintenanceService.getNCANodeVersion() ?: "")
        .replace(variable("BANNER"), NCANode.banner())

    private fun loadHtml(): String = try {
        InputStreamReader(homePage.inputStream, StandardCharsets.UTF_8).use { reader ->
            FileCopyUtils.copyToString(reader)
        }
    } catch (e: IOException) {
        throw UncheckedIOException(e)
    }

    private fun variable(name: String) = "#{$name}"
}
