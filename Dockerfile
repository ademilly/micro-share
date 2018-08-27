FROM golang as builder

WORKDIR /go/src/github.com/ademilly/micro-share
RUN go get github.com/auth0/go-jwt-middleware github.com/gorilla/handlers github.com/lib/pq github.com/ademilly/auth
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build

FROM alpine
ENV JWT_KEY 'helloworld'
ENV PORT '8080'
ENV ROOT /tmp
ENV CERT ''
ENV KEY ''
ENV DBHOSTNAME 'localhost'
ENV DBPORT '5432'
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
WORKDIR /root/
COPY --from=builder /go/src/github.com/ademilly/micro-share/micro-share .
CMD ./micro-share
