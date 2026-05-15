package kz.ncanode.dto.tsp

import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers

enum class TsaPolicy(val policyId: String) {
    TSA_GOST2015_POLICY(KNCAObjectIdentifiers.tsa_gost2015_policy.id),
    TSA_GOST_POLICY(KNCAObjectIdentifiers.tsa_gost_policy.id),
    TSA_GOSTGT_POLICY(KNCAObjectIdentifiers.tsa_gostgt_policy.id),
}
