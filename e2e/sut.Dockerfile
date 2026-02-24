# SPDX-FileCopyrightText: The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine

ADD . /go/src/github.com/pion/mdns
WORKDIR /go/src/github.com/pion/mdns/e2e

RUN go build -tags e2e -o /usr/local/bin/e2e-test .

CMD ["e2e-test"]
