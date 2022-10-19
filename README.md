# TLS ServerNameIndication Test

Run this simple server to test the SNI (Server Name Indication) passed from
the client. This is also useful to verify the information passed from a load balancer.

## Build and Run

```sh
go build -o echosni ./main.go
./echosni
```

Test with `openssl`:

```sh
openssl s_client -connect localhost:8443 -servername server1
```

It should show `server1` after connected.

## Docker Image

```sh
docker run --rm -it -p 8443:8443 easeway/echosni
```

And test using above `openssl` command.
