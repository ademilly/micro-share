package main

// TODO:
// - add user rights management
// - add file mapping

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kennygrant/sanitize"

	"github.com/ademilly/auth"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
)

var (
	port     string
	root     string
	certFile string
	keyFile  string
	jwtKey   string
	addr     string

	dbuser     string
	dbpassword string
	dbname     string
	dbhostname string
	dbport     string
	dbconf     ConnConf

	httpGET  = []string{http.MethodOptions, http.MethodGet}
	httpPOST = []string{http.MethodOptions, http.MethodPost}

	tokenMiddleware *jwtmiddleware.JWTMiddleware
)

const maxUploadSize = 2 * 1024 * 1024 // 2Go

func handleError(err error, w http.ResponseWriter, code int, format string, a ...interface{}) (func(), error) {
	if err != nil {
		return func() {
			msg := fmt.Sprintf(format, a...)
			log.Println(msg)
			http.Error(w, msg, code)
		}, err
	}
	return nil, nil
}

func usernameFromRequestToken(r *http.Request) (string, error) {
	tokenString, err := tokenMiddleware.Options.Extractor(r)
	if err != nil {
		return "", fmt.Errorf("could not extract token string from request: %v", err)
	}

	token, err := jwt.Parse(tokenString, tokenMiddleware.Options.ValidationKeyGetter)
	if err != nil {
		return "", fmt.Errorf("could not parse token string: %v", err)
	}
	return token.Claims.(jwt.MapClaims)["user"].(string), nil
}

func list(w http.ResponseWriter, r *http.Request) {
	username, err := usernameFromRequestToken(r)
	if f, _ := handleError(err, w, http.StatusBadRequest, "could not obtain username from token: %v", err); err != nil {
		f()
		return
	}

	filedata, err := listFiles(dbconf, username)
	if f, _ := handleError(err, w, http.StatusInternalServerError, "could not retrieve files: %v", err); err != nil {
		f()
		return
	}

	results := []string{}
	for _, data := range filedata {
		results = append(results, fmt.Sprintf("%s - %s", data.Path, data.MD5))
	}

	w.Write([]byte(strings.Join(results, "\n")))
}

func get(w http.ResponseWriter, r *http.Request) {
	username, err := usernameFromRequestToken(r)
	if f, _ := handleError(err, w, http.StatusBadRequest, "could not obtain username from token: %v", err); err != nil {
		f()
		return
	}

	md5hash := r.URL.Path[len("/get/"):]
	filepath, err := getFilepath(dbconf, md5hash, username)
	if f, _ := handleError(err, w, http.StatusInternalServerError, "could not obtain filepath: %v", err); err != nil {
		f()
		return
	}

	f, err := os.Open(filepath)
	defer f.Close()
	if f, _ := handleError(err, w, http.StatusBadRequest, "could not read file %s: %v", filepath, err); err != nil {
		f()
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", f.Name()))
	_, err = io.Copy(w, f)

	if f, _ := handleError(err, w, http.StatusInternalServerError, "could not write file to client %s: %v", filepath, err); err != nil {
		w.Header().Del("Content-Type")
		w.Header().Del("Content-Disposition")
		f()
		return
	}
}

func upload(w http.ResponseWriter, r *http.Request) {
	username, err := usernameFromRequestToken(r)
	if f, _ := handleError(err, w, http.StatusBadRequest, "could not obtain username from token: %v", err); err != nil {
		f()
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		f, _ := handleError(err, w, http.StatusBadRequest, "file is too big: %v", err)
		f()
		return
	}

	file, handler, err := r.FormFile("uploadFile")
	if f, err := handleError(err, w, http.StatusBadRequest, "file is invalid: %v", err); err != nil {
		f()
		return
	}
	defer file.Close()

	newPath := filepath.Join(root, sanitize.Name(handler.Filename))
	newFile, err := os.Create(newPath)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not write file: %v", err); err != nil {
		f()
		return
	}
	defer newFile.Close()

	_, err = io.Copy(newFile, file)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not write file: %v", err); err != nil || newFile.Close() != nil {
		f()
		return
	}

	md5String, err := addFile(dbconf, newPath, username)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not register file: %v", err); err != nil {
		f()
		return
	}

	w.Write([]byte(md5String))
}

func newUser(w http.ResponseWriter, r *http.Request) {
	candidate, err := auth.UserFromRequest(r)
	if f, err := handleError(err, w, http.StatusBadRequest, "could not retrieve candidate User from request: %v", err); err != nil {
		f()
		return
	}

	userID, err := addUser(dbconf, candidate)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not create a new user: %v", err); err != nil {
		f()
		return
	}

	w.Write([]byte(strconv.FormatInt(userID, 10)))
}

type groupPayload struct {
	GroupName string `json:"group_name"`
}

func newGroup(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var group groupPayload
	err := decoder.Decode(&group)
	if f, err := handleError(err, w, http.StatusBadRequest, "could not retrieve group data from request: %v", err); err != nil {
		f()
		return
	}

	groupID, err := addGroup(dbconf, group.GroupName)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not create a new group: %v", err); err != nil {
		f()
		return
	}

	w.Write([]byte(strconv.FormatInt(groupID, 10)))
}

type addUserToGroupPayload struct {
	Username  string `json:"username"`
	GroupName string `json:"group_name"`
}

func newMember(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	var relation addUserToGroupPayload
	err := decoder.Decode(&relation)
	if f, err := handleError(err, w, http.StatusBadRequest, "could not retrieve relation data from request: %v", err); err != nil {
		f()
		return
	}

	relationID, err := addUserToGroup(dbconf, relation.Username, relation.GroupName)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not add user %s to group %s: %v", relation.Username, relation.GroupName, err); err != nil {
		f()
		return
	}

	w.Write([]byte(strconv.FormatInt(relationID, 10)))
}

func login(w http.ResponseWriter, r *http.Request) {
	candidate, err := auth.UserFromRequest(r)
	if f, err := handleError(err, w, http.StatusBadRequest, "could not retrieve candidate User from request: %v", err); err != nil {
		f()
		return
	}

	token, err := auth.Login(
		auth.Tokenizer(addr, jwtKey),
		retrieve(dbconf, candidate.Username),
	)(candidate)
	if f, err := handleError(err, w, http.StatusInternalServerError, "could not obtain token for user %s: %v", candidate.Username, err); err != nil {
		f()
		return
	}

	w.Write([]byte(token))
}

func isInArray(s string, arr []string) error {
	stringMap := map[string]bool{}
	for _, str := range arr {
		stringMap[str] = true
	}

	if stringMap[s] {
		return nil
	}
	return fmt.Errorf("%s is not in %v", s, arr)
}

func allow(methods []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := isInArray(r.Method, methods)
		if f, err := handleError(err, w, http.StatusBadRequest, "%s is not in allowed methods: %v", methods, r.Method); err != nil {
			f()
			return
		}

		handler.ServeHTTP(w, r)
	}
}

func init() {
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: micro-share [options...]")
		fmt.Fprintln(os.Stderr, `Environment:
  JWT_KEY: jwt token key
           used for authentication,
           expected to be different than the null string`)
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
	}

	flag.StringVar(&port, "port", "8080", "port number on which to serve")
	flag.StringVar(&root, "root", "/tmp", "path to root directory containing file to be served")
	flag.StringVar(&certFile, "certificate", "", "[optional] path to TLS certificate file")
	flag.StringVar(&keyFile, "key", "", "[optional] path to TLS key file")

	flag.StringVar(&dbuser, "db-user", "microshare", "postgres database username")
	flag.StringVar(&dbpassword, "db-password", "microshare", "postgres database password")
	flag.StringVar(&dbname, "db-name", "microshare", "postgres database name")
	flag.StringVar(&dbhostname, "db-hostname", "localhost", "postgres database hostname")
	flag.StringVar(&dbport, "db-port", "5432", "postgres database port")
}

func main() {
	flag.Parse()
	dbconf = ConnConf{dbuser, dbpassword, dbname, dbhostname, dbport}

	jwtKey = os.Getenv("JWT_KEY")
	if jwtKey == "" {
		log.Fatalf("JWT_KEY environment variable has not been set; it is needed for authentication to work")
	}

	if _, err := ioutil.ReadDir(root); err != nil {
		log.Fatalf("can't list directory %s: %v", root, err)
	}

	tokenMiddleware = auth.TokenMiddleware(jwtKey)

	addr = fmt.Sprintf("0.0.0.0:%s", port)
	handler := http.NewServeMux()

	handler.HandleFunc("/login", allow(httpPOST, login))
	handler.HandleFunc("/new-user", allow(httpPOST, newUser))
	handler.HandleFunc("/new-group", allow(httpPOST, newGroup))
	handler.HandleFunc("/new-member", allow(httpPOST, newMember))

	handler.HandleFunc("/", allow(httpGET, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome to this micro-share!"))
	}))

	handler.HandleFunc("/list", allow(httpGET, auth.Protect(tokenMiddleware, list)))
	handler.HandleFunc("/upload", allow(httpPOST, auth.Protect(tokenMiddleware, upload)))
	handler.HandleFunc("/get/", allow(httpGET, auth.Protect(tokenMiddleware, get)))

	srv := http.Server{
		Handler: handlers.LoggingHandler(os.Stdout, handler),
		Addr:    addr,
	}

	if certFile == "" && keyFile == "" {
		log.Printf("serving on http://%s", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("server stopped: %v\n", err)
		}
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("could not use %s as certificate: %v", certFile, err)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("could not use %s as key: %v", keyFile, err)
	}

	log.Printf("serving on https://%s", addr)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatalf("server stopped: %v\n", err)
	}
}
