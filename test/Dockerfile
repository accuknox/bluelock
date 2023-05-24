FROM ubuntu

RUN apt update -y; apt install -y socat

CMD ["/bluelock/bluelock", "socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash"]
