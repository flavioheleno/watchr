FROM php:8.2-cli-alpine3.18 AS runtime-cli

ARG VERSION=latest

# updated sha512sum
RUN set -eux ; \
  apk add --no-cache --virtual .watchr-rundeps \
    coreutils

# install https://github.com/mlocati/docker-php-extension-installer
RUN set -eux ; \
  curl \
    --silent \
    --fail \
    --location \
    --retry 3 \
    --output /usr/local/bin/install-php-extensions \
    --url https://github.com/mlocati/docker-php-extension-installer/releases/download/2.7.13/install-php-extensions \
  ; \
  echo cbf3df321e90305cd04cc991c7bcd29c0542fe80221c36da2f88d6457be352dce72ca2683a584de1a6cd59dd769dab465880b57e6330eb69ecd200878ee572d5 /usr/local/bin/install-php-extensions | sha512sum --strict --check ; \
  chmod +x /usr/local/bin/install-php-extensions ; \
  install-php-extensions curl filter hash json openssl pcntl

RUN apk del .watchr-rundeps && \
  rm /usr/src/php.tar.xz /usr/src/php.tar.xz.asc

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" && \
    rm "$PHP_INI_DIR/php.ini-development" && \
    echo "date.timezone = UTC"                > /usr/local/etc/php/conf.d/timezone.ini && \
    echo "memory_limit = -1"                  > /usr/local/etc/php/conf.d/memory.ini && \
    echo "variables_order = EGPCS"            > /usr/local/etc/php/conf.d/variables_order.ini && \
    echo "zend.assertions = -1"               > /usr/local/etc/php/conf.d/zend.ini && \
    echo "allow_url_fopen = Off"              > /usr/local/etc/php/conf.d/security.ini && \
    echo "allow_url_include = Off"            >> /usr/local/etc/php/conf.d/security.ini

WORKDIR /app

ENV BOX_REQUIREMENT_CHECKER=0

COPY bin/watchr.phar /usr/bin/watchr
CMD ["/usr/bin/watchr"]

LABEL maintainer="Flavio Heleno <flaviohbatista@gmail.com>" \
      org.opencontainers.image.authors="flaviohbatista@gmail.com" \
      org.opencontainers.image.base.name="ghcr.io/flavioheleno/watchr:${VERSION}" \
      org.opencontainers.image.source="https://github.com/flavioheleno/watchr" \
      org.opencontainers.image.title="Watchr: Command-line Interface" \
      org.opencontainers.image.description="Command-line utility to check for Domain Name and TLS Certificates expiration dates." \
      org.opencontainers.image.url="https://github.com/flavioheleno/watchr" \
      org.opencontainers.image.vendor="Flavio Heleno" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

FROM scratch AS standalone-cli

ARG VERSION=latest

ENV BOX_REQUIREMENT_CHECKER=0

COPY --from=runtime-cli /usr/bin/watchr /watchr

LABEL maintainer="Flavio Heleno <flaviohbatista@gmail.com>" \
      org.opencontainers.image.authors="flaviohbatista@gmail.com" \
      org.opencontainers.image.base.name="ghcr.io/flavioheleno/watchr:${VERSION}-standalone" \
      org.opencontainers.image.source="https://github.com/flavioheleno/watchr" \
      org.opencontainers.image.title="Watchr: Command-line Interface (standalone)" \
      org.opencontainers.image.description="Command-line utility to check for Domain Name and TLS Certificates expiration dates." \
      org.opencontainers.image.url="https://github.com/flavioheleno/watchr" \
      org.opencontainers.image.vendor="Flavio Heleno" \
      org.opencontainers.image.version="${VERSION}-standalone" \
      org.opencontainers.image.licenses="MIT"
