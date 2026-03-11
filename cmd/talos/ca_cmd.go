package main

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/cert"
	"github.com/upsidr/talos/internal/store"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Certificate Authority commands",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the CA (generate CA cert and server cert)",
		RunE:  runCAInit,
	}
	initCmd.Flags().String("kms-key", "", "GCP KMS key resource name (omit for local dev mode)")
	initCmd.Flags().String("subject", "CN=Talos CA,O=UPSIDR", "CA certificate subject DN")
	initCmd.Flags().String("expires-in", "10y", "CA certificate validity")
	initCmd.Flags().String("out-dir", "dev", "Output directory for CA and server files")
	initCmd.Flags().StringSlice("server-hosts", []string{"localhost"}, "Server certificate hostnames")
	initCmd.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(initCmd)
	return cmd
}

func runCAInit(cmd *cobra.Command, args []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	kmsKey, _ := cmd.Flags().GetString("kms-key")
	subjectStr, _ := cmd.Flags().GetString("subject")
	expiresIn, _ := cmd.Flags().GetString("expires-in")
	outDir, _ := cmd.Flags().GetString("out-dir")
	serverHosts, _ := cmd.Flags().GetStringSlice("server-hosts")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	logger, err := initLogger(cfg.Logging)
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	defer logger.Sync()

	validity, err := cert.ParseDuration(expiresIn)
	if err != nil {
		return fmt.Errorf("parse validity: %w", err)
	}

	subject := parseSubjectDN(subjectStr)

	if kmsKey != "" {
		return fmt.Errorf("KMS-backed CA is not yet implemented; omit --kms-key for local dev mode")
	}

	logger.Info("generating local CA", zap.String("out_dir", outDir), zap.String("subject", subjectStr))

	caCert, signer, err := cert.GenerateLocalCA(outDir, subject, validity)
	if err != nil {
		return fmt.Errorf("generate local CA: %w", err)
	}
	defer signer.Close()

	// Generate server certificate
	logger.Info("generating server certificate", zap.Strings("hosts", serverHosts))
	if err := cert.GenerateServerCert(caCert, signer, serverHosts, outDir); err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}

	// Store CA record in database
	ctx := context.Background()
	pool, err := initDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	certStore := store.NewPostgresStore(pool)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	kmsRef := fmt.Sprintf("local:%s/ca.key", outDir)

	caRecord := &store.CertificateAuthority{
		ID:                 uuid.New().String(),
		KMSKeyResourceName: kmsRef,
		SubjectDN:          caCert.Subject.String(),
		CertificatePEM:     string(certPEM),
		CreatedAt:          time.Now(),
		ExpiresAt:          caCert.NotAfter,
		IsActive:           true,
	}

	if err := certStore.InsertCA(ctx, caRecord); err != nil {
		return fmt.Errorf("store CA record: %w", err)
	}

	logger.Info("CA initialized successfully",
		zap.String("ca_id", caRecord.ID),
		zap.String("ca_cert", outDir+"/ca.crt"),
		zap.String("server_cert", outDir+"/server.crt"),
	)

	fmt.Printf("CA initialized:\n")
	fmt.Printf("  CA certificate:     %s/ca.crt\n", outDir)
	fmt.Printf("  CA key:             %s/ca.key\n", outDir)
	fmt.Printf("  Server certificate: %s/server.crt\n", outDir)
	fmt.Printf("  Server key:         %s/server.key\n", outDir)
	fmt.Printf("  CA ID:              %s\n", caRecord.ID)

	return nil
}

// parseSubjectDN parses a simple DN string like "CN=Talos CA,O=UPSIDR" into pkix.Name.
func parseSubjectDN(dn string) pkix.Name {
	name := pkix.Name{}
	for _, part := range splitDN(dn) {
		kv := splitKV(part)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "CN":
			name.CommonName = kv[1]
		case "O":
			name.Organization = append(name.Organization, kv[1])
		case "OU":
			name.OrganizationalUnit = append(name.OrganizationalUnit, kv[1])
		case "C":
			name.Country = append(name.Country, kv[1])
		case "L":
			name.Locality = append(name.Locality, kv[1])
		case "ST":
			name.Province = append(name.Province, kv[1])
		}
	}
	return name
}

func splitDN(dn string) []string {
	var parts []string
	current := ""
	for _, c := range dn {
		if c == ',' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func splitKV(s string) []string {
	for i, c := range s {
		if c == '=' {
			return []string{trimSpace(s[:i]), trimSpace(s[i+1:])}
		}
	}
	return []string{s}
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}
