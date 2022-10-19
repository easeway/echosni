FROM golang:1.18-alpine as build
COPY main.go /
COPY go.mod /
RUN cd / && CGO_ENABLED=0 go build -o /echosni ./main.go

FROM scratch
COPY --from=build /echosni /
EXPOSE 8443
ENTRYPOINT ["/echosni"]
