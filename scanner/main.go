package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rjeff-sudo/sentinelke/scanner/fingerprint"
	"github.com/rjeff-sudo/sentinelke/scanner/portscan"
)

func main() {
	target := flag.String("target", "", "IP address to scan e.g. 192.168.1.1")
	startPort := flag.Int("start", 1, "Start of port range")
	endPort := flag.Int("end", 1024, "End of port range")
	flag.Parse()

	if *target == "" {
		fmt.Println("[!] Please provide a target: -target 192.168.1.1")
		os.Exit(1)
	}

	fmt.Printf("[*] SentinelKE Scanner starting...\n")
	fmt.Printf("[*] Target : %s\n", *target)
	fmt.Printf("[*] Ports  : %d - %d\n\n", *startPort, *endPort)

	// Phase 1 - find open ports
	fmt.Println("[*] Scanning for open ports...")
	results := portscan.ScanHost(*target, *startPort, *endPort, 1*time.Second)

	if len(results) == 0 {
		fmt.Println("[!] No open ports found.")
		os.Exit(0)
	}

	fmt.Printf("[+] %d open port(s) found. Fingerprinting services...\n\n", len(results))

	// Phase 2 - fingerprint each open port
	for _, r := range results {
		var b fingerprint.Banner

		if r.Port == 443 || r.Port == 8443 {
			b = fingerprint.GrabBannerTLS(*target, r.Port, 2*time.Second)
		} else {
			b = fingerprint.GrabBanner(*target, r.Port, 2*time.Second)
		}

		// Print findings
		fmt.Printf("┌─ Port %-6d %s\n", r.Port, b.Service)
		if b.Version != "" {
			fmt.Printf("│  Version : %s\n", b.Version)
		}
		if b.Raw != "" {
			// Truncate long banners for display
			raw := b.Raw
			if len(raw) > 80 {
				raw = raw[:80] + "..."
			}
			fmt.Printf("│  Banner  : %s\n", raw)
		}
		fmt.Printf("│  Risk    : %s\n", b.Risk)
		fmt.Printf("└  Note    : %s\n\n", b.Note)
	}
}