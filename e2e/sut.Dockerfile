# SPDX-FileCopyrightText: The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-alpine

ADD . /go/src/github.com/pion/mdns
WORKDIR /go/src/github.com/pion/mdns

RUN go build -tags e2e -o /usr/local/bin/e2e-test ./e2e

CMD ["e2e-test"]
