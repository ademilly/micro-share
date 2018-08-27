package main

import (
	"database/sql"
	"fmt"

	"github.com/ademilly/auth"
	_ "github.com/lib/pq"
)

func conn(pguser, pgpassword, pgdbname, hostname, port string) (*sql.DB, error) {
	return sql.Open("postgres", fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", pguser, pgpassword, hostname, port, pgdbname))
}

func retrieve(pguser, pgpassword, pgdbname, hostname, port, username string) auth.UserClosure {
	return func() (auth.User, error) {
		db, err := conn(pguser, pgpassword, pgdbname, hostname, port)
		if err != nil {
			return auth.User{}, fmt.Errorf("could not connect to database: %v", err)
		}

		var passhash string
		err = db.QueryRow("SELECT passhash FROM users WHERE username = $1", username).Scan(&passhash)

		return auth.User{Username: username, Hash: passhash}, err
	}
}
