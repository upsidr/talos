package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/cert"
	"github.com/upsidr/talos/internal/issuance"
	"github.com/upsidr/talos/internal/store"
)

func newIssuanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issuance",
		Short: "Certificate issuance server commands",
	}

	serve := &cobra.Command{
		Use:   "serve",
		Short: "Start the Kerberos-authenticated certificate issuance server",
		RunE:  runIssuanceServe,
	}
	serve.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(serve)
	return cmd
}

func runIssuanceServe(cmd *cobra.Command, args []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	if cfg.Issuance == nil {
		return fmt.Errorf("issuance section not configured in %s", cfgPath)
	}

	logger, err := initLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := initDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	certStore := store.NewPostgresStore(pool)

	// Get active CA
	ca, err := certStore.GetActiveCA(ctx)
	if err != nil {
		return fmt.Errorf("get active CA: %w", err)
	}
	if ca == nil {
		return fmt.Errorf("no active CA found; run 'talos ca init' first")
	}

	caCert, err := cert.ParseCertificatePEM([]byte(ca.CertificatePEM))
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	// Load signer (reuse loadSigner from cert_cmd.go)
	signer, err := loadSigner(ca.KMSKeyResourceName)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()

	srv := issuance.NewServer(cfg.Issuance, cfg, certStore, signer, []byte(ca.CertificatePEM), caCert, ca.ID, logger)

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	logger.Info("starting talos issuance server", zap.String("version", version))
	return srv.Run(ctx)
}
