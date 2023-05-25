FROM ubuntu

RUN apt update -y; apt install -y socat curl wget iputils-ping

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash,pty,stderr,setsid,sigint,sane"]
