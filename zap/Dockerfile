FROM zaproxy/zap-stable

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    xvfb \
    x11vnc \
    novnc \
    websockify \
    openbox \
    && rm -rf /var/lib/apt/lists/*

COPY start.sh /start.sh
RUN chmod +x /start.sh

USER zap

EXPOSE 8093 6080

ENTRYPOINT ["/start.sh"]