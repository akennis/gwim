package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failure: %v", err)
		}
	}()

	<-stop
	fmt.Println("Shutting down server...")

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	fmt.Println("Server exiting")
}
