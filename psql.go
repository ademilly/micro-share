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

func addUser(pguser, pgpassword, pgdbname, hostname, port string, candidate auth.User) (int64, error) {
	newUser, err := auth.Hash(candidate)
	if err != nil {
		return 0, fmt.Errorf("could not hash candidate password: %v", err)
	}

	db, err := conn(pguser, pgpassword, pgdbname, hostname, port)
	if err != nil {
		return 0, fmt.Errorf("could not connect to database: %v", err)
	}

	var userID int64
	err = db.QueryRow("INSERT INTO users (username, passhash) VALUES ($1, $2) RETURNING id", newUser.Username, newUser.Hash).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("could not add new user: %v", err)
	}

	return userID, nil
}
