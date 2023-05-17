FROM golang:1.19 AS build

WORKDIR /app
RUN apt update -y; apt install -y libseccomp-dev

ADD . .

RUN go build -o bluelock .

FROM ubuntu
WORKDIR /app
RUN apt update -y; apt install -y libc-dev libseccomp-dev socat curl wget
COPY --from=build /app .
CMD ["./bluelock", "socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash"]
