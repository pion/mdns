#!/bin/sh
# SPDX-FileCopyrightText: The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

# Start dbus (required for avahi-browse D-Bus communication),
# busybox httpd (CGI endpoint for the reverse test), and avahi-daemon.

dbus-daemon --system
httpd -p 8080 -h /var/www
exec avahi-daemon --no-drop-root --no-rlimits --debug
