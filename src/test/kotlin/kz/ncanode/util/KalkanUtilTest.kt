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
})
