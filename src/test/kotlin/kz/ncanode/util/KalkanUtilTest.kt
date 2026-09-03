package kz.ncanode.util

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

class KalkanUtilTest : FunSpec({

    test("OID constants point to NCA GOST 2015 signature algorithms") {
        GOST3410_256_2015 shouldBe "1.2.398.3.10.1.1.2.3.1"
        GOST3410_512_2015 shouldBe "1.2.398.3.10.1.1.2.3.2"
    }

    test("getTspHashAlgorithmByOid pairs GOST 2015-256 cert with Streebog-256 imprint") {
        // Хэш TSP-метки должен соответствовать поколению ключа.
        getTspHashAlgorithmByOid(GOST3410_256_2015) shouldBe "1.2.398.3.10.1.3.2"
        getTspHashAlgorithmByOid(GOST3410_512_2015) shouldBe "1.2.398.3.10.1.3.3"
    }

    test("getTspHashAlgorithmByOid falls back to legacy GOST 34.11 for unknown sig") {
        getTspHashAlgorithmByOid("9.9.9.9") shouldBe "1.2.398.3.10.1.3.1"
    }

    test("getSignMethodByOID returns XMLDSIG URN pair for GOST 2015") {
        val (sigUri, hashUri) = getSignMethodByOID(GOST3410_512_2015)
        sigUri shouldBe "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-512"
        hashUri shouldBe "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-512"
    }

    test("getHashingAlgorithmByOID maps Streebog OIDs to NCA-named labels") {
        getHashingAlgorithmByOID("1.2.398.3.10.1.3.2") shouldBe "GOST3411-2015-256"
        getHashingAlgorithmByOID("1.2.398.3.10.1.3.3") shouldBe "GOST3411-2015-512"
    }

    test("getHashingAlgorithmByOID returns null for unknown OID") {
        getHashingAlgorithmByOID("9.9.9.9").shouldBeNull()
    }

    test("legacy RSA signatures keep their own XMLDSIG and TSP algorithms") {
        // Ключи НУЦ давно на ГОСТ 2015, но подписи прежних поколений всё ещё
        // приходят на проверку, и подменять им алгоритм нельзя.
        val (rsaSha1Sig, rsaSha1Hash) = getSignMethodByOID("1.2.840.113549.1.1.5")
        rsaSha1Sig shouldBe "http://www.w3.org/2001/04/xmldsig-more#rsa-sha1"
        rsaSha1Hash shouldBe "http://www.w3.org/2001/04/xmldsig-more#sha1"

        val (rsaSha256Sig, rsaSha256Hash) = getSignMethodByOID("1.2.840.113549.1.1.11")
        rsaSha256Sig shouldBe "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        rsaSha256Hash shouldBe "http://www.w3.org/2001/04/xmlenc#sha256"

        getTspHashAlgorithmByOid("1.2.840.113549.1.1.5") shouldBe "1.3.14.3.2.26"
        getTspHashAlgorithmByOid("1.2.840.113549.1.1.11") shouldBe "2.16.840.1.101.3.4.2.1"
    }

    test("getSignMethodByOID covers GOST 2015-256 and falls back to legacy GOST 34.310") {
        val (sig256, hash256) = getSignMethodByOID(GOST3410_256_2015)
        sig256 shouldBe "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34102015-gostr34112015-256"
        hash256 shouldBe "urn:ietf:params:xml:ns:pkigovkz:xmlsec:algorithms:gostr34112015-256"

        val (legacySig, legacyHash) = getSignMethodByOID("9.9.9.9")
        legacySig shouldBe "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311"
        legacyHash shouldBe "http://www.w3.org/2001/04/xmldsig-more#gost34311"
    }
})
