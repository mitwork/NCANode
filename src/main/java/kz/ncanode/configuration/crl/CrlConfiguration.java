package kz.ncanode.configuration.crl;

import java.net.URL;
import java.util.Map;

public interface CrlConfiguration {
    boolean isEnabled();
    boolean isCacheEnabled();
    boolean isWarmupEnabled();
    Integer getTtl();
    String getUrl();
    Map<String, URL> getUrlList();
    CrlBaseConfiguration getDelta();
}
