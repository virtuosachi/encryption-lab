# Dockerfile — how to run the Encryption Lab on a hosting service such as Render.
#
# A Dockerfile is a recipe for a small Linux "box" (container) with everything the
# app needs. You don't need Docker on your own computer: the host builds it for you.
#
# We use the official PHP image that comes with the Apache web server. Unlike
# `php -S` (which answers one request at a time), Apache can serve a whole class at once.
# It already includes everything the lab uses: openssl, sodium, pdo_sqlite, mbstring.

FROM php:8.3-apache

# Serve the public/ folder (just like `php -S ... -t public` does locally).
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri -e 's!/var/www/!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Hosting services tell the app which port to listen on through the PORT variable
# (Render uses 10000 by default). Make Apache listen on it.
ENV PORT=10000
RUN sed -ri -e 's/^Listen 80$/Listen ${PORT}/' /etc/apache2/ports.conf \
 && sed -ri -e 's/<VirtualHost \*:80>/<VirtualHost *:${PORT}>/' /etc/apache2/sites-available/000-default.conf

# Show PHP errors as normal messages but don't print warnings into pages.
RUN { echo 'display_errors=Off'; echo 'log_errors=On'; echo 'error_log=/dev/stderr'; } > /usr/local/etc/php/conf.d/lab.ini

# Copy the project in and let Apache's user write to storage/ (keys, "cloud", database).
COPY . /var/www/html/
RUN mkdir -p /var/www/html/storage && chown -R www-data:www-data /var/www/html/storage

EXPOSE 10000
