package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/upsidr/talos/internal/cert"
	"github.com/upsidr/talos/internal/config"
	"github.com/upsidr/talos/internal/store"
)

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate management commands",
	}

	issue := &cobra.Command{
		Use:   "issue [identity]",
		Short: "Issue a new certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  runCertIssue,
	}
	issue.Flags().String("expires-in", "", "Certificate validity duration (e.g., 90d, 365d)")
	issue.Flags().String("out-dir", ".", "Output directory for certificate files")
	issue.Flags().String("passphrase-file", "", "File containing passphrase for PKCS#12 bundle")
	issue.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	revoke := &cobra.Command{
		Use:   "revoke [identity]",
		Short: "Revoke a certificate",
		Args:  cobra.ExactArgs(1),
		RunE:  runCertRevoke,
	}
	revoke.Flags().Int("version", 0, "Certificate version to revoke (0 = latest active)")
	revoke.Flags().Bool("all", false, "Revoke all active versions")
	revoke.Flags().String("reason", "", "Revocation reason (for audit trail)")
	revoke.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	reissue := &cobra.Command{
		Use:   "reissue [identity]",
		Short: "Revoke current and issue a new certificate version",
		Args:  cobra.ExactArgs(1),
		RunE:  runCertReissue,
	}
	reissue.Flags().String("expires-in", "", "Certificate validity duration")
	reissue.Flags().String("out-dir", ".", "Output directory for certificate files")
	reissue.Flags().String("passphrase-file", "", "File containing passphrase for PKCS#12 bundle")
	reissue.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	list := &cobra.Command{
		Use:   "list",
		Short: "List all certificates",
		RunE:  runCertList,
	}
	list.Flags().String("status", "", "Filter by status (active, revoked)")
	list.Flags().StringP("output", "o", "table", "Output format (table, json)")
	list.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	show := &cobra.Command{
		Use:   "show [identity]",
		Short: "Show certificate details",
		Args:  cobra.ExactArgs(1),
		RunE:  runCertShow,
	}
	show.Flags().Int("version", 0, "Certificate version to show (0 = latest)")
	show.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(issue, revoke, reissue, list, show)
	return cmd
}

func runCertIssue(cmd *cobra.Command, args []string) error {
	identity := args[0]
	cfgPath, _ := cmd.Flags().GetString("config")
	expiresIn, _ := cmd.Flags().GetString("expires-in")
	outDir, _ := cmd.Flags().GetString("out-dir")
	passphraseFile, _ := cmd.Flags().GetString("passphrase-file")

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

	certStore := store.NewPostgresStore(pool)
	return issueCert(ctx, certStore, cfg, logger, identity, expiresIn, outDir, passphraseFile)
}

func issueCert(ctx context.Context, certStore *store.PostgresStore, cfg config.Config, logger *zap.Logger, identity, expiresIn, outDir, passphraseFile string) error {
	// Load CA
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

	// Load signer
	signer, err := loadSigner(ca.KMSKeyResourceName)
	if err != nil {
		return err
	}
	defer func() { _ = signer.Close() }()

	// Determine validity
	validity := cfg.Certificate.DefaultValidity
	if expiresIn != "" {
		validity, err = cert.ParseDuration(expiresIn)
		if err != nil {
			return fmt.Errorf("parse validity: %w", err)
		}
	}
	if cfg.Certificate.MaxValidity > 0 && validity > cfg.Certificate.MaxValidity {
		return fmt.Errorf("requested validity %v exceeds maximum %v", validity, cfg.Certificate.MaxValidity)
	}

	// Get next version
	version, err := certStore.GetNextVersion(ctx, identity)
	if err != nil {
		return fmt.Errorf("get next version: %w", err)
	}

	// Issue certificate
	issued, err := cert.IssueClientCert(caCert, signer, cert.IssueOptions{
		Identity:     identity,
		Organization: cfg.Certificate.Organization,
		Validity:     validity,
	})
	if err != nil {
		return fmt.Errorf("issue certificate: %w", err)
	}

	// Store in database
	certRecord := &store.Certificate{
		ID:                uuid.New().String(),
		SerialNumber:      issued.SerialNumber,
		Identity:          identity,
		Version:           version,
		CAID:              ca.ID,
		FingerprintSHA256: issued.Fingerprint,
		SubjectDN:         issued.SubjectDN,
		Status:            store.StatusActive,
		IssuedAt:          time.Now(),
		ExpiresAt:         issued.Certificate.NotAfter,
		IssuedBy:          "talos-cli",
	}
	if err := certStore.InsertCert(ctx, certRecord); err != nil {
		return fmt.Errorf("store certificate: %w", err)
	}

	// Read passphrase
	passphrase := ""
	if passphraseFile != "" {
		data, err := os.ReadFile(passphraseFile)
		if err != nil {
			return fmt.Errorf("read passphrase file: %w", err)
		}
		passphrase = strings.TrimSpace(string(data))
	}

	// Write output files
	files, err := cert.WriteOutputFiles(issued, outDir, passphrase, identity, version)
	if err != nil {
		return fmt.Errorf("write output files: %w", err)
	}

	logger.Info("certificate issued",
		zap.String("identity", identity),
		zap.Int("version", version),
		zap.String("fingerprint", issued.Fingerprint),
	)

	fmt.Printf("Certificate issued:\n")
	fmt.Printf("  Identity:    %s\n", identity)
	fmt.Printf("  Version:     %d\n", version)
	fmt.Printf("  Serial:      %s\n", issued.SerialNumber)
	fmt.Printf("  Fingerprint: %s\n", issued.Fingerprint)
	fmt.Printf("  Expires:     %s\n", issued.Certificate.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Cert file:   %s\n", files.CertPath)
	fmt.Printf("  Key file:    %s\n", files.KeyPath)
	if files.P12Path != "" {
		fmt.Printf("  PKCS#12:     %s\n", files.P12Path)
	}

	return nil
}

func runCertRevoke(cmd *cobra.Command, args []string) error {
	identity := args[0]
	cfgPath, _ := cmd.Flags().GetString("config")
	versionFlag, _ := cmd.Flags().GetInt("version")
	revokeAll, _ := cmd.Flags().GetBool("all")
	reason, _ := cmd.Flags().GetString("reason")

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

	certStore := store.NewPostgresStore(pool)

	// Build query options
	activeStatus := store.StatusActive
	opts := store.ListCertsOptions{
		Identity: &identity,
		Status:   &activeStatus,
	}
	if versionFlag > 0 && !revokeAll {
		opts.Version = &versionFlag
	}

	certs, err := certStore.ListCerts(ctx, opts)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no active certificates found for %s", identity)
	}

	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}

	for _, c := range certs {
		if err := certStore.UpdateCertStatus(ctx, c.ID, store.StatusRevoked, reasonPtr); err != nil {
			return fmt.Errorf("revoke certificate %s v%d: %w", c.Identity, c.Version, err)
		}
		logger.Info("certificate revoked",
			zap.String("identity", c.Identity),
			zap.Int("version", c.Version),
			zap.String("fingerprint", c.FingerprintSHA256),
		)
		fmt.Printf("Revoked: %s v%d (fingerprint: %s)\n", c.Identity, c.Version, c.FingerprintSHA256)
	}

	return nil
}

func runCertReissue(cmd *cobra.Command, args []string) error {
	identity := args[0]
	cfgPath, _ := cmd.Flags().GetString("config")
	expiresIn, _ := cmd.Flags().GetString("expires-in")
	outDir, _ := cmd.Flags().GetString("out-dir")
	passphraseFile, _ := cmd.Flags().GetString("passphrase-file")

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

	certStore := store.NewPostgresStore(pool)

	// Revoke all active versions
	activeStatus := store.StatusActive
	opts := store.ListCertsOptions{
		Identity: &identity,
		Status:   &activeStatus,
	}
	certs, err := certStore.ListCerts(ctx, opts)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	reason := "reissued"
	for _, c := range certs {
		if err := certStore.UpdateCertStatus(ctx, c.ID, store.StatusRevoked, &reason); err != nil {
			return fmt.Errorf("revoke certificate %s v%d: %w", c.Identity, c.Version, err)
		}
		logger.Info("revoked for reissue",
			zap.String("identity", c.Identity),
			zap.Int("version", c.Version),
		)
	}

	// Issue new version
	return issueCert(ctx, certStore, cfg, logger, identity, expiresIn, outDir, passphraseFile)
}

func runCertList(cmd *cobra.Command, args []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	statusFilter, _ := cmd.Flags().GetString("status")
	outputFormat, _ := cmd.Flags().GetString("output")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := initDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	certStore := store.NewPostgresStore(pool)

	opts := store.ListCertsOptions{}
	if statusFilter != "" {
		s := store.CertificateStatus(statusFilter)
		opts.Status = &s
	}

	certs, err := certStore.ListCerts(ctx, opts)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	if outputFormat == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(certs)
	}

	// Table format
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "IDENTITY\tVERSION\tSTATUS\tISSUED\tEXPIRES\tFINGERPRINT")
	for _, c := range certs {
		fp := c.FingerprintSHA256
		if len(fp) > 23 {
			fp = fp[:23] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n",
			c.Identity, c.Version, c.Status,
			c.IssuedAt.Format("2006-01-02"),
			c.ExpiresAt.Format("2006-01-02"),
			fp,
		)
	}
	return w.Flush()
}

func runCertShow(cmd *cobra.Command, args []string) error {
	identity := args[0]
	cfgPath, _ := cmd.Flags().GetString("config")
	versionFlag, _ := cmd.Flags().GetInt("version")

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	ctx := context.Background()
	pool, err := initDatabase(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer pool.Close()

	certStore := store.NewPostgresStore(pool)

	opts := store.ListCertsOptions{
		Identity: &identity,
	}
	if versionFlag > 0 {
		opts.Version = &versionFlag
	}

	certs, err := certStore.ListCerts(ctx, opts)
	if err != nil {
		return fmt.Errorf("list certificates: %w", err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates found for %s", identity)
	}

	// Show the latest version if no specific version requested
	c := certs[len(certs)-1]

	fmt.Printf("Identity:          %s\n", c.Identity)
	fmt.Printf("Version:           %d\n", c.Version)
	fmt.Printf("Serial:            %s\n", c.SerialNumber)
	fmt.Printf("Status:            %s\n", c.Status)
	fmt.Printf("Subject:           %s\n", c.SubjectDN)
	fmt.Printf("Fingerprint:       %s\n", c.FingerprintSHA256)
	fmt.Printf("CA ID:             %s\n", c.CAID)
	fmt.Printf("Issued At:         %s\n", c.IssuedAt.Format(time.RFC3339))
	fmt.Printf("Expires At:        %s\n", c.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Issued By:         %s\n", c.IssuedBy)
	if c.RevokedAt != nil {
		fmt.Printf("Revoked At:        %s\n", c.RevokedAt.Format(time.RFC3339))
	}
	if c.RevocationReason != nil {
		fmt.Printf("Revocation Reason: %s\n", *c.RevocationReason)
	}

	return nil
}

// loadSigner detects "local:" prefix and returns appropriate Signer.
func loadSigner(kmsKeyRef string) (cert.Signer, error) {
	if strings.HasPrefix(kmsKeyRef, "local:") {
		keyPath := strings.TrimPrefix(kmsKeyRef, "local:")
		return cert.NewLocalSigner(keyPath)
	}
	return nil, fmt.Errorf("unsupported KMS key reference: %s (only local: prefix is supported)", kmsKeyRef)
}
