<!--
SPDX-FileCopyrightText: The Pion community <https://pion.ly>
SPDX-License-Identifier: MIT
-->

# Specifications

Run `go run fetch.go` to download and process the RFC and draft specs.

The script:
- Downloads specs from IETF/RFC editor
- Cleans up page breaks and headers/footers
- Splits each spec into chapters (stored in `<spec-name>/`)
- Generates an index file for each spec

Useful for agents and developers to reference specific sections.
