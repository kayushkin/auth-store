package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authstore "github.com/kayushkin/auth-store"
	"github.com/kayushkin/auth-store/internal/server"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runMigrate(os.Args[2:])
		return
	}

	var (
		port    int
		dbPath  string
		addr    string
		bindAll bool
	)
	flag.IntVar(&port, "port", 8303, "HTTP server port")
	flag.StringVar(&dbPath, "db", "", "database path (default: ~/.config/auth-store/auth.db)")
	flag.StringVar(&addr, "addr", "", "explicit listen address (overrides --port and --bind-all)")
	flag.BoolVar(&bindAll, "bind-all", false, "bind to 0.0.0.0 instead of 127.0.0.1")
	flag.Parse()

	store, err := authstore.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer store.Close()

	store.RegisterDefaultOAuthProviders()

	listenAddr := addr
	if listenAddr == "" {
		host := "127.0.0.1"
		if bindAll {
			host = "0.0.0.0"
		}
		listenAddr = fmt.Sprintf("%s:%d", host, port)
	}

	authToken := os.Getenv("AUTHSTORE_TOKEN")
	if authToken == "" {
		log.Println("WARNING: AUTHSTORE_TOKEN not set — /api/* endpoints are unauthenticated")
	}
	callbackURL := os.Getenv("AUTHSTORE_CALLBACK_URL")
	if callbackURL == "" {
		callbackURL = fmt.Sprintf("http://localhost:%d/oauth/callback", port)
	}

	srv := server.New(server.Config{
		Store:       store,
		AuthToken:   authToken,
		CallbackURL: callbackURL,
	})

	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: srv.Handler(),
	}

	log.Printf("auth-store listening on %s (db=%s, callback=%s)", listenAddr, store.Path(), callbackURL)

	idleConnsClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(ctx); err != nil {
			log.Printf("shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
	<-idleConnsClosed
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	from := fs.String("from", "", "source: aiauth | apiauth | mailstack")
	dst := fs.String("db", "", "destination auth-store db path (default ~/.config/auth-store/auth.db)")
	dryRun := fs.Bool("dry-run", false, "print intended writes without persisting")
	fs.Parse(args)
	if *from == "" {
		fmt.Fprintln(os.Stderr, "auth-store migrate --from <aiauth|apiauth|mailstack> [--db PATH] [--dry-run]")
		os.Exit(2)
	}
	store, err := authstore.Open(*dst)
	if err != nil {
		log.Fatalf("open dest store: %v", err)
	}
	defer store.Close()

	switch *from {
	case "aiauth":
		if err := migrateAiauth(store, *dryRun); err != nil {
			log.Fatalf("migrate aiauth: %v", err)
		}
	case "apiauth":
		if err := migrateApiauth(store, *dryRun); err != nil {
			log.Fatalf("migrate apiauth: %v", err)
		}
	case "mailstack":
		if err := migrateMailstack(store, *dryRun); err != nil {
			log.Fatalf("migrate mailstack: %v", err)
		}
	default:
		log.Fatalf("unknown source: %s", *from)
	}
}
