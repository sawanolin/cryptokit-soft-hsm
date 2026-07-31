ARG ALPINE_VERSION=3.24

# 使用 Docker Hub 官方 Alpine 镜像，并保留镜像内置的 Alpine 官方软件仓库。
FROM alpine:${ALPINE_VERSION} AS alpine-base

# builder、web-builder 和运行阶段都需要 Python，复用公共层，
# 避免多个阶段重复安装 python3。
FROM alpine-base AS python-base
RUN apk add --no-cache python3

FROM python-base AS builder
RUN apk add --no-cache \
    build-base \
    cmake \
    ninja \
    perl \
    linux-headers

COPY openhitls /src/openhitls
RUN cmake -S /src/openhitls -B /build/openhitls -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/openhitls \
    -DHITLS_BUILD_PROFILE=full \
    && cmake --build /build/openhitls -j2 \
    && cmake --install /build/openhitls

COPY sdfx /src/sdfx
RUN cmake -S /src/sdfx -B /build/sdfx -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/sdfx \
    -DOpenHiTLS_ROOT_DIR=/opt/openhitls \
    -DSDFX_TRANSPORT_TYPE=tcp \
    -DBUILD_TESTS=ON \
    -DBUILD_EXAMPLES=OFF \
    && cmake --build /build/sdfx -j2 \
    && cmake --install /build/sdfx

FROM python-base AS web-builder
RUN apk add --no-cache py3-pip

COPY web/requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/sdfx-web \
    && /opt/sdfx-web/bin/pip install \
    --no-cache-dir \
    --timeout 120 \
    --retries 10 \
    -r /tmp/requirements.txt

FROM python-base AS runtime
RUN apk add --no-cache supervisor \
    && addgroup -S sdfx \
    && adduser -S -G sdfx sdfx

LABEL org.opencontainers.image.title="CryptoKit SoftHSM" \
    org.opencontainers.image.version="1.0.1" \
    org.opencontainers.image.authors="sawanolin and CryptoKit SoftHSM contributors" \
    org.opencontainers.image.source="https://github.com/sawanolin/cryptokit-soft-hsm" \
    org.opencontainers.image.url="https://hub.docker.com/r/sawanolin/cryptokit-soft-hsm" \
    org.opencontainers.image.documentation="https://github.com/sawanolin/cryptokit-soft-hsm/blob/main/README.md" \
    org.opencontainers.image.licenses="AGPL-3.0-only"

COPY --from=builder /opt/openhitls/lib /opt/openhitls/lib
COPY --from=builder /opt/sdfx/bin/sdfxd /usr/local/bin/sdfxd
COPY --from=web-builder /opt/sdfx-web /opt/sdfx-web
COPY sdfx/config/sdfx-container.conf /etc/sdfx/sdfx.conf
COPY web/backend /opt/sdfx-web-app
COPY LICENSE /opt/sdfx-web-app/static/LICENSE.txt
COPY server/supervisord.conf /etc/supervisord.conf
COPY server/entrypoint.sh /usr/local/bin/sdfx-entrypoint
COPY server/healthcheck.sh /usr/local/bin/sdfx-healthcheck

COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/licenses/cryptokit-soft-hsm/
COPY sdfx/LICENSE /usr/share/licenses/cryptokit-soft-hsm/SDFX-LICENSE
COPY openhitls/LICENSE /usr/share/licenses/cryptokit-soft-hsm/openHiTLS-LICENSE
COPY openhitls/Third_Party_Open_Source_Software_Notice /usr/share/licenses/cryptokit-soft-hsm/openHiTLS-THIRD-PARTY-NOTICE

RUN chmod 0755 /usr/local/bin/sdfx-entrypoint /usr/local/bin/sdfx-healthcheck \
    && mkdir -p /var/lib/sdfx/keys/kek \
    /var/lib/sdfx/keys/sm2/sign \
    /var/lib/sdfx/keys/sm2/enc \
    /var/lib/sdfx/files \
    /var/lib/sdfx/web \
    /run/sdfx \
    && chown -R sdfx:sdfx /var/lib/sdfx /run/sdfx

ENV LD_LIBRARY_PATH=/opt/openhitls/lib
ENV SDFX_DATA_DIR=/var/lib/sdfx
ENV SDFX_ADMIN_TOKEN_FILE=/run/sdfx/admin.token

EXPOSE 18081 18080
VOLUME ["/var/lib/sdfx"]

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 CMD ["/usr/local/bin/sdfx-healthcheck"]

ENTRYPOINT ["/usr/local/bin/sdfx-entrypoint"]
