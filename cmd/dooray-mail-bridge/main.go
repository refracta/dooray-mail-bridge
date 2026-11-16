package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-smtp"
	"github.com/joho/godotenv"
	"github.com/refracta/dooray-mail-bridge/internal/bridge"
	"github.com/refracta/dooray-mail-bridge/internal/config"
	"github.com/refracta/dooray-mail-bridge/internal/dooray"
	"github.com/refracta/dooray-mail-bridge/internal/session"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Printf("dooray-mail-bridge: %v", err)
		os.Exit(1)
	}
}

func run() error {
	envFile := flag.String("env-file", ".env", "optional dotenv configuration file")
	check := flag.Bool("check", false, "authenticate and check mailbox access, then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if err := godotenv.Load(*envFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not read environment file")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	web, err := session.New(cfg.Session)
	if err != nil {
		return err
	}
	defer web.Close()
	provider := dooray.New(web, cfg.Session.Email)
	authCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	log.Print("Authenticating upstream HTTP session")
	err = provider.Authenticate(authCtx, cfg.Session.Username, cfg.Session.Password)
	cancel()
	if err != nil {
		return fmt.Errorf("upstream login failed: %w", err)
	}
	if *check {
		folders, err := provider.Folders(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Authentication OK; %d mailboxes accessible over HTTP\n", len(folders))
		return nil
	}
	mailBridge, err := bridge.New(provider, cfg.DataDir, cfg.PollInterval)
	if err != nil {
		return err
	}
	defer mailBridge.Close()
	var tlsConfig *tls.Config
	if !cfg.InsecureLocal {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return errors.New("could not load TLS certificate/key")
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	}
	listen := func(addr string) (net.Listener, error) {
		if tlsConfig != nil {
			return tls.Listen("tcp", addr, tlsConfig)
		}
		return net.Listen("tcp", addr)
	}
	imapListener, err := listen(cfg.IMAPAddress)
	if err != nil {
		return fmt.Errorf("IMAP listen: %w", err)
	}
	defer imapListener.Close()
	smtpListener, err := listen(cfg.SMTPAddress)
	if err != nil {
		return fmt.Errorf("SMTP listen: %w", err)
	}
	defer smtpListener.Close()
	imapServer := imapserver.New(&imapserver.Options{NewSession: mailBridge.NewIMAPSession, Caps: bridge.Capabilities(), InsecureAuth: cfg.InsecureLocal})
	defer imapServer.Close()
	smtpServer := smtp.NewServer(mailBridge.SMTPBackend())
	smtpServer.Domain = "dooray-mail-bridge"
	smtpServer.AllowInsecureAuth = cfg.InsecureLocal
	smtpServer.MaxMessageBytes = cfg.MaxMessageBytes
	smtpServer.MaxRecipients = 100
	smtpServer.ReadTimeout = 5 * time.Minute
	smtpServer.WriteTimeout = 5 * time.Minute
	defer smtpServer.Close()
	defer mailBridge.Cancel()
	serveErrors := make(chan error, 2)
	go func() { serveErrors <- imapServer.Serve(imapListener) }()
	go func() { serveErrors <- smtpServer.Serve(smtpListener) }()
	log.Printf("Ready: IMAP %s, SMTP %s, TLS=%t", imapListener.Addr(), smtpListener.Addr(), tlsConfig != nil)
	select {
	case <-ctx.Done():
		return nil
	case err := <-serveErrors:
		return err
	}
}
