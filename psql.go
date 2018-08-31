package main

import (
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/ademilly/auth"
	_ "github.com/lib/pq"
)

// ConnConf wraps necessary variable to build conn string to db
type ConnConf struct {
	User     string
	Password string
	DBName   string
	Hostname string
	Port     string
}

func (c ConnConf) String() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", c.User, c.Password, c.Hostname, c.Port, c.DBName)
}

func (c ConnConf) conn() (*sql.DB, error) {
	return sql.Open("postgres", c.String())
}

func retrieve(conf ConnConf, username string) auth.UserClosure {
	return func() (auth.User, error) {
		db, err := conf.conn()
		if err != nil {
			return auth.User{}, fmt.Errorf("could not connect to database: %v", err)
		}

		var passhash string
		err = db.QueryRow("SELECT passhash FROM users WHERE username = $1", username).Scan(&passhash)

		return auth.User{Username: username, Hash: passhash}, err
	}
}

func addUser(conf ConnConf, candidate auth.User) (int64, error) {
	newUser, err := auth.Hash(candidate)
	if err != nil {
		return 0, fmt.Errorf("could not hash candidate password: %v", err)
	}

	db, err := conf.conn()
	if err != nil {
		return 0, fmt.Errorf("could not connect to database: %v", err)
	}

	var userID int64
	err = db.QueryRow("INSERT INTO users (username, passhash) VALUES ($1, $2) RETURNING id", newUser.Username, newUser.Hash).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("could not add new user %s: %v", newUser.Username, err)
	}

	var groupID int64
	err = db.QueryRow("INSERT INTO groups (groupname) VALUES ($1) RETURNING id", newUser.Username).Scan(&groupID)
	if err != nil {
		return 0, fmt.Errorf("could not create user group %s: %v", newUser.Username, err)
	}

	var relationID int64
	err = db.QueryRow("INSERT INTO relations (groupID, userID) VALUES ($1, $2) RETURNING id", groupID, userID).Scan(&relationID)
	if err != nil {
		return 0, fmt.Errorf("could not create relation groupID %d - userID %d: %v", groupID, userID, err)
	}

	return userID, nil
}

func addGroup(conf ConnConf, groupname string) (int64, error) {
	db, err := conf.conn()
	if err != nil {
		return 0, fmt.Errorf("could not connect to database: %v", err)
	}

	var groupID int64
	err = db.QueryRow("INSERT INTO groups (groupname) VALUES ($1) RETURNING id", groupname).Scan(&groupID)
	if err != nil {
		return 0, fmt.Errorf("could not add group %s: %v", groupname, err)
	}

	return groupID, nil
}

func addUserToGroup(conf ConnConf, username, groupname string) (int64, error) {
	db, err := conf.conn()
	if err != nil {
		return 0, fmt.Errorf("could not connect to database: %v", err)
	}

	var groupID int64
	err = db.QueryRow("SELECT id FROM groups WHERE groupname = $1", groupname).Scan(&groupID)
	if err != nil {
		return 0, fmt.Errorf("could not retrieve id for group %s: %v", groupname, err)
	}

	var userID int64
	err = db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err != nil {
		return 0, fmt.Errorf("could not retrieve id for user %s: %v", groupname, err)
	}

	var relationID int64
	err = db.QueryRow("INSERT INTO relations (groupID, userID) VALUES ($1, $2) RETURNING id", groupID, userID).Scan(&relationID)
	if err != nil {
		return 0, fmt.Errorf("could not add user %s to group %s: %v", username, groupname, err)
	}

	return relationID, nil
}

func md5FromString(str string) string {
	h := md5.New()
	io.WriteString(h, str)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// FileData maps to files schema
type FileData struct {
	Path string
	MD5  string
}

func listFiles(conf ConnConf, username string) ([]FileData, error) {
	db, err := conf.conn()
	if err != nil {
		return nil, fmt.Errorf("could not connect to database: %v", err)
	}

	rows, err := db.Query(`SELECT files.filepath, files.md5 
	FROM files, users, relations, readers
	WHERE users.username = $1 
		AND relations.userid = users.id
		AND readers.groupid = relations.groupid
		AND files.id = readers.fileid`, username)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve files: %v", err)
	}
	defer rows.Close()

	data := []FileData{}
	for rows.Next() {
		var (
			filepath string
			md5hash  string
		)
		if err := rows.Scan(&filepath, &md5hash); err != nil {
			return nil, fmt.Errorf("could not read results of query: %v", err)
		}

		data = append(data, FileData{filepath, md5hash})
	}

	return data, nil
}

func addFile(conf ConnConf, filepath string, username string) (string, error) {
	db, err := conf.conn()
	if err != nil {
		return "", fmt.Errorf("could not connect to database: %v", err)
	}

	var groupID int64
	err = db.QueryRow("SELECT id FROM groups WHERE groupname = $1", username).Scan(&groupID)
	if err != nil {
		return "", fmt.Errorf("could not retrieve groupID: %v", err)
	}

	var fileID int64
	var md5hash string
	err = db.QueryRow(
		"INSERT INTO files (filepath, md5, ownerID) VALUES ($1, $2, $3) RETURNING id, md5",
		filepath, md5FromString(filepath), groupID,
	).Scan(&fileID, &md5hash)
	if err != nil {
		return "", fmt.Errorf("could not register file: %v", err)
	}

	var readersID int64
	err = db.QueryRow(
		"INSERT INTO readers (fileID, groupID) VALUES ($1, $2) RETURNING id",
		fileID, groupID,
	).Scan(&readersID)

	return md5hash, nil
}

func addReader(conf ConnConf, md5hash, groupname string) (int64, error) {
	db, err := conf.conn()
	if err != nil {
		return 0, fmt.Errorf("could not connect to database: %v", err)
	}

	var fileID int64
	err = db.QueryRow("SELECT id FROM files WHERE md5 = $1", md5hash).Scan(&fileID)
	if err != nil {
		return 0, fmt.Errorf("could not retrieve fileID: %v", err)
	}

	var groupID int64
	err = db.QueryRow("SELECT id FROM groups WHERE groupname = $1", groupname).Scan(&groupID)
	if err != nil {
		return 0, fmt.Errorf("could not retrieve groupID: %v", err)
	}

	var readerID int64
	err = db.QueryRow("INSERT INTO readers (fileID, groupID) VALUES ($1, $2) RETURNING id", fileID, groupID).Scan(&readerID)
	if err != nil {
		return 0, fmt.Errorf("could not add reader: %v", err)
	}

	return readerID, nil
}

func getFilepath(conf ConnConf, md5hash, username string) (string, error) {
	db, err := conf.conn()
	if err != nil {
		return "", fmt.Errorf("could not connect to database: %v", err)
	}

	var groupID int64
	err = db.QueryRow("SELECT id FROM groups WHERE groupname = $1", username).Scan(&groupID)
	if err != nil {
		return "", fmt.Errorf("could not retrieve groupID: %v", err)
	}

	var filepath string
	err = db.QueryRow("SELECT filepath FROM files WHERE md5 = $1 AND ownerID = $2", md5hash, groupID).Scan(&filepath)
	if err != nil {
		return "", fmt.Errorf("could not retrieve filepath: %v", err)
	}

	return filepath, nil
}
