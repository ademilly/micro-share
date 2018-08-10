package main

// TODO:
// - add bdd for auth
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

	token, err := auth.Login(auth.Tokenizer(addr, jwtKey), func() (auth.User, error) {
		return auth.Hash(candidate)
	})(candidate)
	if err != nil {
		msg := fmt.Sprintf("could not obtain token for user %s: %v", candidate.Username, err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	w.Write([]byte(token))
}

func protect(tokenMiddleware *jwtmiddleware.JWTMiddleware, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenMiddleware.Handler(http.HandlerFunc(handler)).ServeHTTP(w, r)
	}
}

func init() {
	jwtKey = os.Getenv("JWT_KEY")
	if jwtKey == "" {
		log.Fatalf("JWT_KEY environment variable has not been set; it is needed for authentication to work")
	}
}

func main() {
	flag.StringVar(&port, "port", "8080", "port number on which to serve")
	flag.StringVar(&root, "root", "/tmp", "path to root directory containing file to be served")
	flag.StringVar(&certFile, "certificate", "", "[optional] path to TLS certificate file")
	flag.StringVar(&keyFile, "key", "", "[optional] path to TLS key file")
	flag.Parse()

	if _, err := ioutil.ReadDir(root); err != nil {
		log.Fatalf("can't list directory %s: %v", root, err)
	}

	tokenMiddleware := auth.TokenMiddleware(jwtKey)

	addr = fmt.Sprintf("0.0.0.0:%s", port)
	handler := http.NewServeMux()

	handler.HandleFunc("/login", login)

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("welcome to this micro-share!"))
	})
	handler.HandleFunc("/get/", protect(tokenMiddleware, get))

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
