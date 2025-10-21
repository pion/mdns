## Example
There are many ways to use the example, as described in the [README](../README.md) at the root of this repo.

Note: the mDNS server responds to queries for `pion-test.local`.

### 1. Start a generic mDNS server
Run the following from the root:
```sh
go run examples/server/main.go
```

This spins up the mDNS server.

### 2. Query from the client
Run the following from the root:

#### Linux
```sh
go run examples/query/main.go
```

#### macOS
```
dns-sd -q pion-test.local
```

#### Or using avahi
```
avahi-resolve -a pion-test.local
```

Once you've queried from the client, you should receive a basic response from the mDNS server, which is printed out by the client, comprised of three parts:
1. the answer to the query
2. the source of the mDNS server (aka the server's IP)
3. any related errors

## Example finished!

An alternative to step 1 is to instead run:
```sh
go run examples/server/publish_ip/main.go -ip=[IP]
```

where `[IP]` is a valid ip address (defaults to `1.2.3.4`). This determines what ip address the mDNS server is hosted on.

At this point you can now see how easy it is to spin up an mDNS server, query it from a client. Now go do something with the response! :)
