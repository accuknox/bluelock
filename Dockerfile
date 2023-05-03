FROM golang:1.19 AS build

WORKDIR /app

ADD . .

RUN apt update -y; apt install -y gcc libseccomp-dev
RUN go build -o bluelock .

FROM ubuntu
WORKDIR /app
RUN apt update -y; apt install -y libc-dev libseccomp-dev socat
COPY --from=build /app .
CMD ["./bluelock", "socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash"]
