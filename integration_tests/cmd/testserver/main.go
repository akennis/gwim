package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/akennis/gwim"
)

func main() {
	addr := flag.String("addr", ":8080", "Address to listen on")
	useNTLM := flag.Bool("use-ntlm", true, "Use NTLM if true, otherwise Kerberos")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if username, ok := gwim.User(r); ok {
			fmt.Fprintf(os.Stderr, "TestServer: Authenticated user %s\n", username)
			fmt.Fprintf(w, "Hello, %s", username)
		} else {
			fmt.Fprintf(os.Stderr, "TestServer: Unauthorized access\n")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	})

	handler, err := gwim.NewSSPIHandler(mux, *useNTLM)
	if err != nil {
		log.Fatalf("Failed to create SSPI handler: %v", err)
	}

	server := &http.Server{
		Addr:    *addr,
		Handler: handler,
	}

	if *useNTLM {
		gwim.ConfigureNTLM(server)
	}

	// Print actual address if port 0 was used
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *addr, err)
	}
	fmt.Printf("Test server listening on %s (NTLM=%v)\n", ln.Addr().String(), *useNTLM)

	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failure: %v", err)
	}
}
