package kz.ncanode.dto.ocsp;

import kz.ncanode.dto.certificate.CertificateRevocation;
import kz.ncanode.dto.certificate.CertificateRevocationStatus;
import lombok.Builder;
import lombok.Data;

import java.security.cert.CRLReason;
import java.util.Date;

@Data
@Builder(toBuilder = true)
public class OcspStatus {
    private OcspResult result;
    private Date revocationTime;
    private int revocationReason;
    private String message;
    private String url;

    public boolean isActive() {
        return getResult().equals(OcspResult.ACTIVE);
    }

    public CertificateRevocationStatus toCertificateRevocationStatus() {
        return CertificateRevocationStatus.builder()
            .revoked(result.equals(OcspResult.REVOKED))
            .revocationTime(revocationTime)
            .by(CertificateRevocation.OCSP)
            .reason(mapReason())
            .build();
    }

    /**
     * Маппит int-код причины отзыва из OCSP-ответа (RFC 5280 §5.3.1)
     * в имя {@link CRLReason}. Ordinals enum-а совпадают с RFC-кодами 1:1
     * (UNSPECIFIED=0, KEY_COMPROMISE=1, ...AA_COMPROMISE=10), включая
     * placeholder UNUSED=7.
     *
     * Для не-REVOKED статусов используем поле {@code message} как раньше
     * (обычно "OK").
     */
    private String mapReason() {
        if (result != OcspResult.REVOKED) {
            return message;
        }
        // -1 ставится в OcspService когда IllegalStateException — поле
        // отсутствует в ответе. По RFC 5280 §5.3.1 отсутствие = unspecified.
        if (revocationReason < 0) {
            return CRLReason.UNSPECIFIED.name();
        }
        CRLReason[] values = CRLReason.values();
        if (revocationReason < values.length) {
            return values[revocationReason].name();
        }
        return CRLReason.UNSPECIFIED.name();
    }
}
