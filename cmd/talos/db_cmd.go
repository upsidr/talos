package main

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

//go:embed schema.sql
var schemaSQL string

func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database management commands",
	}

	migrateCmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply database schema",
		RunE:  runDBMigrate,
	}
	migrateCmd.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(migrateCmd)
	return cmd
}

func runDBMigrate(cmd *cobra.Command, args []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	logger, err := initLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer func() { _ = logger.Sync() }()

	ctx := context.Background()
	pool, err := initDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	logger.Info("applying database schema", zap.String("host", cfg.Database.Host), zap.String("database", cfg.Database.Name))

	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	logger.Info("database schema applied successfully")
	fmt.Println("Database schema applied successfully.")
	return nil
}
