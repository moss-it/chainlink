#syntax=docker/dockerfile:1.2
FROM --platform=$BUILDPLATFORM golang:1.15.12-buster AS build

ARG COMMIT_SHA
ARG ENVIRONMENT
ARG TARGETPLATFORM

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...

RUN go build -o chainlink ./core/

FROM debian:buster

COPY --from=build /go/src/app/chainlink /

EXPOSE 6688
ENTRYPOINT ["/chainlink"]
CMD ["help"]
