package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/proxy"
	"github.com/upsidr/talos/internal/store"
)

var version = "dev"

func main() {
	root := &cobra.Command{
		Use:   "talos",
		Short: "Certificate-Authenticated TCP Proxy",
	}

	root.AddCommand(
		newProxyCmd(),
		newCertCmd(),
		newCACmd(),
		newVersionCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("talos %s\n", version)
		},
	}
}

func newProxyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "TCP proxy server commands",
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "Start the TCP proxy server",
		RunE:  runProxyStart,
	}
	start.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(start)
	return cmd
}

func runProxyStart(cmd *cobra.Command, args []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	logger, err := initLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := initDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	certStore := store.NewPostgresStore(pool)
	srv := proxy.NewServer(cfg, certStore, logger)

	// Graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		cancel()
	}()

	logger.Info("starting talos proxy", zap.String("version", version))
	return srv.Run(ctx)
}
