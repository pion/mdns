module github.com/pion/mdns/v2/e2e

go 1.24.0

replace github.com/pion/mdns/v2 => ../

require (
	github.com/pion/mdns/v2 v2.0.0-00010101000000-000000000000
	golang.org/x/net v0.50.0
)

require (
	github.com/pion/logging v0.2.4 // indirect
	golang.org/x/sys v0.41.0 // indirect
)
