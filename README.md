# micro-share

Go File sharing HTTP server with auth and user rights management

## setup

### fileserver

Using `go get`:

```bash
    # dependencies
    $ go get github.com/auth0/go-jwt-middleware github.com/gorilla/handlers github.com/lib/pq github.com/kennygrant/sanitize github.com/ademilly/auth
    # micro-share
    $ go get github.com/ademilly/micro-share
```

Using `docker`:

```bash
    $ docker-compose build
```

### psql

docker-compose sets up a psql database, storing user data

```bash
    $ docker-compose up -d
    Creating network "micro-share_default" with the default driver
    Creating micro-share_pgsql_1 ... done
```

POSTGRES_USER and POSTGRES_PASSWORD can be defined using a `.env` file or through environment variables.

To initialize the psql database, use the `psql/schema.sql` file with your preferred tool to interact with a psql database. Using the `psql` CLI tool:

```bash
    $ PGUSER=validusername PGPASSWORD=validpassword psql -h localhost -p 5432 < psql/schema.sql
```

## usage

### docker-compose

The default `docker-compose.yml` file expects a values for the following environment variables:

- JWT_KEY => string used to generate JWT tokens
- CERT    => path to a certificate file (used for https)
- KEY     => path to a key file (used for https)

Certificate and key file are expected to live in a local `certs/` directory for the default `docker-compose.yml`.

### fileserver

#### cli

```bash
    $ micro-share -h
    Usage: micro-share [options...]
    Environment:
      JWT_KEY: jwt token key
               used for authentication,
               expected to be different than the null string
    Options:
      -certificate string
            [optional] path to TLS certificate file
      -key string
            [optional] path to TLS key file
      -port string
            port number on which to serve (default "8080")
      -root string
            path to root directory containing file to be served (default "/tmp")

    $ JWT_TOKEN=something micro-share
    YYYY/MM/DD HH:mm:ss serving on http://0.0.0.0:8080

    $ JWT_TOKEN=something micro-share -port 80 -root path/to/dir
    YYYY/MM/DD HH:mm:ss serving on http://0.0.0.0:80

    $ JWT_TOKEN=something micro-share -certificate mydomain.crt -key mydomain.key -port 443 -root path/to/dir
    YYYY/MM/DD HH:mm:ss serving on https://0.0.0.0:443
```

The JWT_KEY environment variable is used to initialize the token middleware; thus a token generated by a micro-share service at login with a certain JWT_KEY value can not be used to access another micro-share service using another JWT_KEY value.

#### routes

- `/` used for health checking; serves a welcome message
- `/login` POST to login; data should be send as json in request body
- `/new-user` POST to create new-user; data should be send as json in request body
- `/upload` POST file to upload file
- `/get/base64md5hash` GET to download file matching `base64md5hash`; is protected by JWT token

#### examples

Health check:

```bash
    $ curl https://micro-share.mydomain.com
    welcome to this micro-share!
```

Login:

```bash
    $ curl -X POST -H 'Content-Type: application/json' -d '{ "username": "validusername", "password": "validpassword" }' https://micro-share.mydomain.com/login
    SOME.JWT.TOKEN
```

New User:

```bash
    $ curl -X POST -H 'Content-Type: application/json' -d '{ "username": "validusername", "password": "validpassword" }' https://micro-share.mydomain.com/new-user
    SOME_ID
```

Upload file:

```bash
    $ curl -F 'uploadFile=@path/to/file' -H "Authorization: Bearer SOME.JWT.TOKEN" https://micro-share.mydomain.com/upload
    base64md5hash
```

List files:

```bash
    $ curl -H 'Authorization: Bearer SOME.JWT.TOKEN' https://micro-share.mydomain.com/list
    somefile - base64md5hash
    ...
```

Download file:

```bash
    $ curl -H "Authorization: Bearer SOME.JWT.TOKEN" https://micro-share.mydomain.com/get/base64md5hash
    content of file
```

```bash
    $ wget --header "Authorization: Bearer SOME.JWT.TOKEN" https://micro-share.mydomain.com/get/base64md5hash
    => download content of target file to new file at path base64md5hash
```
