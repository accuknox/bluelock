FROM golang:1.20 AS build
WORKDIR /build

# install build-deps
RUN apt update -y; apt install -y libseccomp-dev
ADD . .

#build bluelock
RUN go build -o bluelock .

# final image
FROM scratch
WORKDIR /
COPY --from=build /build/bluelock .
#ENTRYPOINT ["cp", "/build/bluelock", "/bluelock"]
