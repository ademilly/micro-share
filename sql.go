package main

import (
	"database/sql"
	"fmt"

	"github.com/ademilly/auth"
	_ "github.com/lib/pq"
)

func conn(hostname, port string) (*sql.DB, error) {
	return sql.Open("postgres", fmt.Sprintf("postgres://%s:%s@%s:%s/microshare?sslmode=disable", "microshare", "microshare", hostname, port))
}

func retrieve(hostname, port, username string) auth.UserClosure {
	return func() (auth.User, error) {
		db, err := conn(hostname, port)
		if err != nil {
			return auth.User{}, fmt.Errorf("could not connect to database: %v", err)
		}

		var passhash string
		err = db.QueryRow("SELECT passhash FROM users WHERE username = $1", username).Scan(&passhash)

		fmt.Printf("%+v\n", passhash)
		return auth.User{Username: username, Hash: passhash}, err
	}
}
