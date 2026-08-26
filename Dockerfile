FROM amazoncorretto:25-alpine

# Профиль памяти сервиса: живой heap после прогрева — порядка 30 МБ
# (CRL-индексы лежат в mmap-файлах рядом с CRL, а не в куче), плюс до ~25 МБ
# временных массивов на время перестроения индекса крупного CRL. Потолок в
# 512 МБ оставлен с запасом на подпись объёмных документов: он ограничивает
# рост, но не занимается — SerialGC вместе с *HeapFreeRatio отдаёт неиспользуемое
# обратно ОС, а не держит committed на пике.
#
# ВАЖНО: ENTRYPOINT ниже — shell-форма с exec. В exec-форме ("java", "-jar")
# переменная $JAVA_OPTS не разворачивается, и прежние настройки не применялись
# вообще: JVM брала дефолтные 25% памяти хоста (замерено: committed heap 1.6 ГБ).
ENV JAVA_OPTS="-Xms64m -Xmx512m -XX:+UseSerialGC -XX:MaxMetaspaceSize=256m -XX:MaxHeapFreeRatio=30 -XX:MinHeapFreeRatio=10 -XX:+ExitOnOutOfMemoryError"
EXPOSE 14579
WORKDIR /app
ARG artifact=build/libs/NCANode.jar
COPY $artifact /app/NCANode.jar
RUN mkdir /app/cache
VOLUME /app/cache
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar NCANode.jar \"$@\"", "--"]
HEALTHCHECK --interval=20s --timeout=30s --retries=7 \
    CMD wget -O - http://127.0.0.1:14579/actuator/health | grep -v DOWN || exit 1
