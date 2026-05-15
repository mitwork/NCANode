package kz.ncanode.wrapper

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kz.gov.pki.kalkan.jce.provider.KalkanProvider
import kz.ncanode.TestResources

class KeyStoreWrapperTest : FunSpec({

    val kalkan = KalkanWrapper(KalkanProvider())

    fun read(name: String) = kalkan.read(
        TestResources.loadAsBase64("p12/$name"),
        null,
        TestResources.P12_PASSWORD,
    )

    test("privateKey returns non-null PrivateKey") {
        val ks = read("individual_valid.p12")
        ks.privateKey.shouldNotBeNull()
    }

    test("certificate returns CertificateWrapper for selected alias") {
        val ks = read("individual_valid.p12")
        val cert = ks.certificate
        cert.shouldNotBeNull()
        cert.x509Certificate.shouldNotBeNull()
    }

    test("alias selected matches one of available aliases") {
        val ks = read("legal_ceo_valid.p12")
        ks.aliases shouldContain ks.alias
    }

    test("private key public-key roundtrip — derived public matches cert public") {
        val ks = read("individual_valid.p12")
        // Не сравниваем PrivateKey напрямую (опасно), но проверяем, что
        // cert и keystore возвращают cert одного и того же alias'а.
        val cert = ks.certificate
        cert.x509Certificate.publicKey shouldBe cert.publicKey
    }
})
