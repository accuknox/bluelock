FROM ubuntu

RUN apt update -y; apt install -y socat curl wget iputils-ping

RUN echo 'root:toor' | chpasswd

RUN useradd --create-home --shell /bin/bash user1
RUN echo 'user1:user1' | chpasswd
COPY file.txt /home/user1/file.txt
RUN chown user1:user1 /home/user1/file.txt

USER user1

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:bash,pty,stderr,setsid,sigint,sane"]
