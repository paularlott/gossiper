# The PHP test app on FrankenPHP: symfony/mercure 0.7 (legacy protocol, /publish, /discover) and 0.9 (Mercure 1.0,
# /v1/publish, /v1/discover). Used for several containers: without a built-in hub (they talk to Gossiper) and with
# one (the references).
FROM composer:2 AS vendor-legacy
WORKDIR /app
COPY legacy/composer.json ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader

FROM composer:2 AS vendor-v1
WORKDIR /app
COPY v1/composer.json ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader

FROM dunglas/frankenphp:latest
WORKDIR /app
COPY --from=vendor-legacy /app/vendor /app/vendor-legacy
COPY --from=vendor-v1 /app/vendor /app/vendor-v1
COPY public /app/public
