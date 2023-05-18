FROM golang:1.20 AS build
WORKDIR /build
RUN apt update -y; apt install -y libseccomp-dev
ADD . .
RUN go build -o bluelock .

FROM ubuntu
WORKDIR /build
COPY --from=build /build .
ENTRYPOINT ["cp", "/build/bluelock", "/bluelock"]
