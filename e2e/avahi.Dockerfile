# SPDX-FileCopyrightText: The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

FROM alpine:3.23

RUN apk add --no-cache avahi avahi-tools dbus busybox-extras \
    && mkdir -p /var/run/dbus

COPY e2e/avahi-daemon.conf /etc/avahi/avahi-daemon.conf
COPY e2e/http.service /etc/avahi/services/http.service
COPY e2e/cgi-bin/browse /var/www/cgi-bin/browse
COPY e2e/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /var/www/cgi-bin/browse /entrypoint.sh \
    && chmod +x /var/www/cgi-bin/browse /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
