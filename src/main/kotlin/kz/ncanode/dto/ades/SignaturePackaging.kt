package kz.ncanode.dto.ades

/**
 * Способ размещения подписи относительно подписываемых данных
 * (ETSI EN 319 132-1).
 *
 *  - [ENVELOPED] — подпись вкладывается в сам подписываемый документ;
 *  - [ENVELOPING] — документ вкладывается внутрь подписи (`ds:Object`);
 *  - [DETACHED] — подпись хранится отдельно от данных.
 */
enum class SignaturePackaging {
    ENVELOPED,
    ENVELOPING,
    DETACHED,
}
