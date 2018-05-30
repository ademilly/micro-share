package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
)

var (
	port     string
	root     string
	certFile string
	keyFile  string
)

func writeTo(text string, w http.ResponseWriter) {
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

		w.WriteHeader(http.StatusNotFound)
		writeTo("file does not exist :(", w)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", f.Name()))
	_, err = io.Copy(w, f)

	if err != nil {
		log.Printf("could not write file to client %s: %v", filename, err)

		w.Header().Del("Content-Type")
		w.Header().Del("Content-Disposition")

		w.WriteHeader(http.StatusInternalServerError)
		writeTo("something failed :(", w)
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

	addr := fmt.Sprintf("localhost:%s", port)
	handler := http.NewServeMux()

	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeTo("welcome to this micro-share instance ;)", w)
	})
	handler.HandleFunc("/get/", get)

	srv := http.Server{
		Handler: handler,
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
	if err := srv.ListenAndServeTLS("certs/localhost.crt", "certs/localhost.key"); err != nil {
		log.Fatalf("server stopped: %v\n", err)
	}
}
