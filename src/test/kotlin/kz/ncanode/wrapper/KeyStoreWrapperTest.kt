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

    test("private/public keypair roundtrip — privateKey signs, cert publicKey verifies") {
        // Раньше тут было `x509Certificate.publicKey shouldBe cert.publicKey` —
        // тавтология (cert.publicKey = get() = x509Certificate.publicKey, X==X).
        // Настоящая проверка: приватный ключ keystore и публичный ключ его cert'а
        // — пара. Подписываем приватным, проверяем публичным cert'а.
        val ks = read("individual_valid.p12")
        val cert = ks.certificate
        val data = "ncanode-keypair-roundtrip".toByteArray()
        val algName = cert.x509Certificate.sigAlgName

        val signer = java.security.Signature.getInstance(algName, KalkanProvider.PROVIDER_NAME)
        signer.initSign(ks.privateKey)
        signer.update(data)
        val signature = signer.sign()

        val verifier = java.security.Signature.getInstance(algName, KalkanProvider.PROVIDER_NAME)
        verifier.initVerify(cert.publicKey)
        verifier.update(data)
        verifier.verify(signature) shouldBe true
    }
})
