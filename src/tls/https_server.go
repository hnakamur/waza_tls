package main

import (
	// "fmt"
	// "io"
	"log"
	"net/http"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("This is an example server.\n"))
	// fmt.Fprintf(w, "This is an example server.\n")
	// io.WriteString(w, "This is an example server.\n")
}

func main() {
	http.HandleFunc("/", HelloServer)
	err := http.ListenAndServeTLS(":8443", "naruh.dev.crt", "naruh.dev.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
