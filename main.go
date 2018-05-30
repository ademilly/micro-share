package main

// TODO:
// - add bdd for auth
// - add "New User" feature
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
	"path"

	"github.com/ademilly/micro-share/auth"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/gorilla/handlers"
)

var (
	port     string
	root     string
	certFile string
	keyFile  string
)

func writeTo(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/text")
	if _, err := w.Write([]byte(text)); err != nil {
		log.Printf("could not write to http.ResponseWriter: %v", err)
	}
}

func get(w http.ResponseWriter, r *http.Request) {
	filename := path.Join(root, r.URL.Path[len("/get/"):])

	f, err := os.Open(filename)
	defer f.Close()
	if err != nil {
		log.Printf("could not read file %s: %v", filename, err)

		http.Error(w, "file does not exist :(", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", f.Name()))
	_, err = io.Copy(w, f)

	if err != nil {
		log.Printf("could not write file to client %s: %v", filename, err)

		w.Header().Del("Content-Type")
		w.Header().Del("Content-Disposition")

		http.Error(w, "file transfer failed on our side :(", http.StatusInternalServerError)
	}
}

func login(tokenizer func(string) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		defer r.Body.Close()

		var candidate auth.User
		err := decoder.Decode(&candidate)

		if err != nil {
			log.Printf("could not read request body: %v", err)

			http.Error(w, `request should be { "username": "USERNAME", "password": "PASSWORD" }`, http.StatusBadRequest)
			return
		}

		err = auth.CheckHash(candidate, func() (auth.User, error) {
			return auth.Hash(candidate)
		})
		if err != nil {
			log.Println("candidate does not provide valid user / password couple")

			http.Error(w, "this is not a valid user / password", http.StatusUnauthorized)
			return
		}

		token, err := tokenizer(candidate.Username)
		if err != nil {
			log.Printf("could not obtain token for user %s: %v", candidate.Username, err)

			http.Error(w, fmt.Sprintf("could not obtain token for user %s :(", candidate.Username), http.StatusInternalServerError)
			return
		}

		writeTo(w, token)
	}
}

func protect(tokenMiddleware *jwtmiddleware.JWTMiddleware, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenMiddleware.Handler(http.HandlerFunc(handler)).ServeHTTP(w, r)
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

	jwtKey := os.Getenv("JWT_KEY")
	if jwtKey == "" {
		log.Fatalf("JWT_KEY environment variable has not been set; it is needed for authentication to work")
	}

	tokenMiddleware := auth.TokenMiddleware(jwtKey)

	addr := fmt.Sprintf("0.0.0.0:%s", port)
	handler := http.NewServeMux()

	handler.HandleFunc("/login", login(auth.Tokenizer(addr, jwtKey)))

	handler.HandleFunc("/", protect(tokenMiddleware, func(w http.ResponseWriter, r *http.Request) {
		writeTo(w, "welcome to this micro-share instance ;)")
	}))
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
