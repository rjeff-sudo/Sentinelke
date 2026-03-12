package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rjeff-sudo/sentinelke/scanner/arp"
)

func main() {
	// Command line flags - run with: sudo ./scanner -iface eth0 -subnet 192.168.1.0/24
	iface := flag.String("iface", "eth0", "Network interface to scan on")
	subnet := flag.String("subnet", "192.168.1.0/24", "Subnet to scan e.g. 192.168.1.0/24")
	flag.Parse()

	fmt.Printf("[*] SentinelKE Scanner starting...\n")
	fmt.Printf("[*] Interface : %s\n", *iface)
	fmt.Printf("[*] Subnet    : %s\n\n", *subnet)

	devices, err := arp.DiscoverDevices(*iface, *subnet)
	if err != nil {
		fmt.Printf("[!] Scan failed: %v\n", err)
		os.Exit(1)
	}

	if len(devices) == 0 {
		fmt.Println("[!] No devices found. Check your interface name and subnet.")
		os.Exit(1)
	}

	fmt.Printf("[+] %d device(s) found:\n\n", len(devices))
	for _, d := range devices {
		fmt.Printf("    IP: %-18s  MAC: %s\n", d.IP, d.MAC)
	}
}