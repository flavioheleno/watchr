FROM php:8.2-cli-alpine3.22 AS build

WORKDIR /app

# updated sha256sum
RUN set -eux ; \
  apk upgrade --no-cache --available && \
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
    --url https://github.com/mlocati/docker-php-extension-installer/releases/download/2.8.0/install-php-extensions \
  ; \
  echo 2b3357e1621a440bb94902b665f6cce18c47f7ac7b736b9a8f7155a517c3d26b /usr/local/bin/install-php-extensions | sha256sum --strict --check ; \
  chmod +x /usr/local/bin/install-php-extensions ; \
  install-php-extensions curl filter hash json openssl pcntl

COPY composer.* .

RUN --mount=type=bind,target=/usr/local/bin/composer,source=/composer,from=composer/composer:2.8.9-bin@sha256:c9bda63056674836406cacfbbdd8ef770fb4692ac419c967034225213c64e11b \
    composer install --no-progress --no-dev --prefer-dist --optimize-autoloader --no-interaction

COPY bin/ bin/
COPY config/ config/
COPY src/ src/
COPY box.json .

RUN --mount=type=bind,target=/usr/local/bin/composer,source=/composer,from=composer/composer:2.8.9-bin@sha256:c9bda63056674836406cacfbbdd8ef770fb4692ac419c967034225213c64e11b \
    --mount=type=bind,target=/usr/local/bin/box,source=/box.phar,from=boxproject/box:4.6.6@sha256:2d5ea70231d17e8a8846312d6ebc2f19681e709f06ce3e146c3070411e843beb \
    box compile

FROM php:8.2-cli-alpine3.22 AS runtime-cli

WORKDIR /app

ENV BOX_REQUIREMENT_CHECKER=0

RUN apk upgrade --no-cache --available && \
    rm /usr/src/php.tar.xz /usr/src/php.tar.xz.asc && \
    rm /usr/local/bin/docker-php-ext-*  /usr/local/bin/docker-php-source

ARG VERSION=latest

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" && \
    rm "$PHP_INI_DIR/php.ini-development" && \
    echo "date.timezone = UTC"                > /usr/local/etc/php/conf.d/timezone.ini && \
    echo "memory_limit = -1"                  > /usr/local/etc/php/conf.d/memory.ini && \
    echo "variables_order = EGPCS"            > /usr/local/etc/php/conf.d/variables_order.ini && \
    echo "zend.assertions = -1"               > /usr/local/etc/php/conf.d/zend.ini && \
    echo "allow_url_fopen = Off"              > /usr/local/etc/php/conf.d/security.ini && \
    echo "allow_url_include = Off"            >> /usr/local/etc/php/conf.d/security.ini && \
    echo "zend_extension=opcache"             > /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.enabled=1"                  >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.enable_cli=1"               >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.memory_consumption=192"     >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.interned_strings_buffer=16" >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.max_accelerated_files=4000" >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.validate_timestamps=0"      >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.fast_shutdown=0"            >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.use_cwd=1"                  >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.save_comments=0"            >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.jit_buffer_size=100M"       >> /usr/local/etc/php/conf.d/opcache.ini && \
    echo "opcache.jit=1255"                   >> /usr/local/etc/php/conf.d/opcache.ini

COPY --from=build /app/bin/watchr.phar                                         /usr/bin/watchr
COPY --from=build /usr/local/lib/php/extensions/no-debug-non-zts-20220829/*.so /usr/local/lib/php/extensions/no-debug-non-zts-20220829/
COPY --from=build /usr/local/etc/php/conf.d/*.ini                              /usr/local/etc/php/conf.d/
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

ENV BOX_REQUIREMENT_CHECKER=0

ARG VERSION=latest

COPY --from=build /app/bin/watchr.phar /watchr

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
