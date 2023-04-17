FROM golang:1.19

WORKDIR /app

ADD . .

RUN apt update -y
RUN apt install -y libc-dev gcc libseccomp-dev
RUN go build -o bluelock .
RUN cd test; gcc -o reader filereader.c; cd ../;

CMD ["./bluelock", "./test/reader"]
