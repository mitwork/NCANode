package kz.ncanode.configuration.crl;

import kz.ncanode.util.Util;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.util.Map;

@Slf4j
@Getter
@Setter
public class CrlBaseConfiguration implements CrlConfiguration {
    private boolean enabled = true;
    /**
     * Если true — распарсенные и подпись-верифицированные CRL'и
     * кэшируются в памяти до изменения файла на диске. Без кэша на каждый
     * verify-call идёт повторный парсинг + signature verify, что критично
     * для крупных GOST CRL'ей (десятки секунд на запрос).
     */
    private boolean cacheEnabled = true;
    /**
     * Если true — при старте все CRL'и из disk-кэша предзагружаются и
     * подпись-верифицируются в in-memory cache. Первый пользовательский
     * verify-запрос не тратит время на парсинг крупных GOST CRL'ей.
     *
     * При включённом warmup HealthIndicator {@code crlWarmup} держит
     * статус DOWN пока прогрев не завершён — load balancer не пошлёт
     * на инстанс трафик, пока он реально готов отвечать быстро.
     */
    private boolean warmupEnabled = false;
    private Integer ttl;
    private String url;
    private CrlBaseConfiguration delta;

    public Map<String, URL> getUrlList() {
        return Util.urlMap(getUrl(), log);
    }
}
