FROM golang:1.19 AS build

WORKDIR /app

ADD . .

RUN apt update -y; apt install -y gcc libseccomp-dev
RUN go build -o bluelock .
RUN cd test; gcc -o reader filereader.c; cd ../;

FROM ubuntu
WORKDIR /app
RUN apt update -y; apt install -y libc-dev libseccomp-dev
COPY --from=build /app .
CMD ["./bluelock", "./test/reader"]
