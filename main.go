package main

// TODO:
// - add "New User" feature
// - add user rights management
// - add file mapping

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/ademilly/auth"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/gorilla/handlers"
)

var (
	port     string
	root     string
	certFile string
	keyFile  string
	jwtKey   string
	addr     string

	dbhostname string
	dbport     string

	httpGET  = []string{http.MethodOptions, http.MethodGet}
	httpPOST = []string{http.MethodOptions, http.MethodPost}
)

func get(w http.ResponseWriter, r *http.Request) {
	filename := path.Join(root, r.URL.Path[len("/get/"):])

	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		msg := fmt.Sprintf("could not read file %s: %v", filename, err)
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", f.Name()))
	_, err = io.Copy(w, f)

	if err != nil {
		w.Header().Del("Content-Type")
		w.Header().Del("Content-Disposition")

		msg := fmt.Sprintf("could not write file to client %s: %v", filename, err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	candidate, err := auth.UserFromRequest(r)
	if err != nil {
		msg := fmt.Sprintf("could not retrieve candidate User from request: %v", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	token, err := auth.Login(auth.Tokenizer(addr, jwtKey), retrieve(dbhostname, dbport, candidate.Username))(candidate)
	if err != nil {
		msg := fmt.Sprintf("could not obtain token for user %s: %v", candidate.Username, err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	w.Write([]byte(token))
}

func isInArray(s string, arr []string) bool {
	stringMap := map[string]bool{}
	for _, str := range arr {
		stringMap[str] = true
	}

	return stringMap[s]
}

func allow(methods []string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isInArray(r.Method, methods) {
			msg := fmt.Sprintf("%s is not in allowed methods: %v", methods, r.Method)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		handler.ServeHTTP(w, r)
	}
}

func protect(tokenMiddleware *jwtmiddleware.JWTMiddleware, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenMiddleware.Handler(http.HandlerFunc(handler)).ServeHTTP(w, r)
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

	flag.StringVar(&dbhostname, "db-hostname", "localhost", "postgres database hostname")
	flag.StringVar(&dbport, "db-port", "5432", "postgres database port")
}

func main() {
	flag.Parse()
	jwtKey = os.Getenv("JWT_KEY")
	if jwtKey == "" {
		log.Fatalf("JWT_KEY environment variable has not been set; it is needed for authentication to work")
	}

	if _, err := ioutil.ReadDir(root); err != nil {
		log.Fatalf("can't list directory %s: %v", root, err)
	}

	tokenMiddleware := auth.TokenMiddleware(jwtKey)

	addr = fmt.Sprintf("0.0.0.0:%s", port)
	handler := http.NewServeMux()

	handler.HandleFunc("/login", allow(httpPOST, login))

	handler.HandleFunc("/", allow(httpGET, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome to this micro-share!"))
	}))
	handler.HandleFunc("/get/", allow(httpGET, protect(tokenMiddleware, get)))

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
