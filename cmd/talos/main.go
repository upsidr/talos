package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
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
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	start.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(start)
	return cmd
}

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate management commands",
	}

	issue := &cobra.Command{
		Use:   "issue [identity]",
		Short: "Issue a new certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	issue.Flags().String("expires-in", "", "Certificate validity duration (e.g., 90d, 365d)")
	issue.Flags().String("out-dir", ".", "Output directory for certificate files")
	issue.Flags().String("passphrase-file", "", "File containing passphrase for PKCS#12 bundle")
	issue.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	revoke := &cobra.Command{
		Use:   "revoke [identity]",
		Short: "Revoke a certificate",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	revoke.Flags().Int("version", 0, "Certificate version to revoke")
	revoke.Flags().Bool("all", false, "Revoke all versions")
	revoke.Flags().String("reason", "", "Revocation reason (for audit trail)")
	revoke.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	reissue := &cobra.Command{
		Use:   "reissue [identity]",
		Short: "Issue a new certificate version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	reissue.Flags().String("expires-in", "", "Certificate validity duration")
	reissue.Flags().String("out-dir", ".", "Output directory for certificate files")
	reissue.Flags().String("passphrase-file", "", "File containing passphrase for PKCS#12 bundle")
	reissue.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	list := &cobra.Command{
		Use:   "list",
		Short: "List all certificates",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	list.Flags().String("status", "", "Filter by status (active, revoked)")
	list.Flags().StringP("output", "o", "table", "Output format (table, json)")
	list.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	show := &cobra.Command{
		Use:   "show [identity]",
		Short: "Show certificate details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	show.Flags().Int("version", 0, "Certificate version to show")
	show.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(issue, revoke, reissue, list, show)
	return cmd
}

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Certificate Authority commands",
	}

	init := &cobra.Command{
		Use:   "init",
		Short: "Initialize the CA (generate CA cert from KMS key)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: implement
			return fmt.Errorf("not implemented")
		},
	}
	init.Flags().String("kms-key", "", "GCP KMS key resource name")
	init.Flags().String("subject", "", "CA certificate subject DN")
	init.Flags().String("expires-in", "10y", "CA certificate validity")
	init.Flags().StringP("config", "c", "talos.yaml", "Path to configuration file")

	cmd.AddCommand(init)
	return cmd
}
