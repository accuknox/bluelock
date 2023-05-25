FROM golang:1.20 AS build
WORKDIR /build
RUN apt update -y; apt install -y libseccomp-dev
ADD . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bluelock .

FROM busybox:stable
WORKDIR /build
COPY --from=build /build .
ENTRYPOINT ["cp", "/build/bluelock", "/kubearmor"]
