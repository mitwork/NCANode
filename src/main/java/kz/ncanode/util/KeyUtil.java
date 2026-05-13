package kz.ncanode.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@UtilityClass
public class KeyUtil {

    /**
     * Преобразует алиасы в список
     * @param key ЭЦП
     * @return Список алиасов
     */
    public static List<String> getAliases(KeyStore key) {
        var list = new ArrayList<String>();

        try {
            var aliases = key.aliases();

            while (aliases.hasMoreElements()) {
                list.add(aliases.nextElement());
            }
        } catch (KeyStoreException e) {
            log.warn("Could not enumerate keystore aliases", e);
        }

        return list;
    }
}
