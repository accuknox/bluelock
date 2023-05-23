FROM ubuntu

RUN apt update -y; apt install -y socat

COPY --from=delusionaloptimist/bluelock:latest /bluelock /bluelock

CMD ["/bluelock", "socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash"]
