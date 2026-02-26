package cmd

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/dominikschlosser/ssi-debugger/internal/proxy"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	proxyTarget    string
	proxyPort      int
	dashboardPort  int
	noDashboard    bool
	allTraffic     bool
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start a debugging reverse proxy for OID4VP/VCI flows",
	Long:  "Starts a reverse proxy that intercepts, classifies, and decodes OID4VP/VCI traffic between a wallet and a verifier/issuer. Point your wallet at the proxy port instead of the target.",
	RunE:  runProxy,
}

func init() {
	proxyCmd.Flags().StringVar(&proxyTarget, "target", "", "URL of the verifier/issuer to proxy to (required)")
	proxyCmd.Flags().IntVar(&proxyPort, "port", 9090, "Proxy listen port")
	proxyCmd.Flags().IntVar(&dashboardPort, "dashboard", 9091, "Dashboard listen port")
	proxyCmd.Flags().BoolVar(&noDashboard, "no-dashboard", false, "Disable web dashboard")
	proxyCmd.Flags().BoolVar(&allTraffic, "all-traffic", false, "Show all traffic, not just OID4VP/VCI requests")
	_ = proxyCmd.MarkFlagRequired("target")
	rootCmd.AddCommand(proxyCmd)
}

func runProxy(cmd *cobra.Command, args []string) error {
	targetURL, err := url.Parse(proxyTarget)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		return fmt.Errorf("target URL must include a host (e.g. http://localhost:8080)")
	}

	cfg := proxy.Config{
		TargetURL:     targetURL,
		ProxyPort:     proxyPort,
		DashboardPort: dashboardPort,
		NoDashboard:   noDashboard,
		AllTraffic:    allTraffic,
	}

	srv := proxy.NewServer(cfg)

	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.Faint)

	cyan.Printf("SSI Debugger Proxy\n")
	dim.Println("───────────────────────────────────────")
	fmt.Printf("  Target:    %s\n", proxyTarget)
	fmt.Printf("  Proxy:     http://localhost:%d\n", proxyPort)
	if !noDashboard {
		fmt.Printf("  Dashboard: http://localhost:%d\n", dashboardPort)
	}
	dim.Println("───────────────────────────────────────")
	fmt.Println()

	if !noDashboard {
		dashboard := proxy.NewDashboard(srv.Store(), dashboardPort)
		go func() {
			if err := dashboard.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Printf("Dashboard error: %v\n", err)
			}
		}()
	}

	return http.ListenAndServe(fmt.Sprintf(":%d", proxyPort), srv)
}
