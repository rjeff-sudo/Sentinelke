package arp

import (
	"net"
	"net/netip"
	"time"

	"github.com/mdlayher/arp"
)

// Device represents a single machine discovered on the LAN
type Device struct {
	IP  string
	MAC string
}

// DiscoverDevices sends ARP requests across a subnet and returns
// every device that responds
func DiscoverDevices(interfaceName string, subnet string) ([]Device, error) {
	var devices []Device

	// Step 1 - Get the network interface by name (e.g. "eth0", "wlan0")
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	// Step 2 - Parse the subnet e.g. "192.168.1.0/24"
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, err
	}

	// Step 3 - Open an ARP client on the interface
	client, err := arp.Dial(iface)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Step 4 - Set a deadline so we don't wait forever
	client.SetDeadline(time.Now().Add(3 * time.Second))

	// Step 5 - Send ARP requests to every IP in the subnet concurrently
	go func() {
		for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
			// Send ARP request - "who has this IP?"
			client.Request(ip)
		}
	}()

	// Step 6 - Collect all replies until the deadline
	seen := make(map[string]bool) // avoid duplicates

	for {
		// Read one ARP packet at a time
		packet, _, err := client.Read()
		if err != nil {
			// Deadline exceeded - we are done listening
			break
		}

		// Only process replies (not requests)
		if packet.Operation != arp.OperationReply {
			continue
		}

		ip := packet.SenderIP.String()

		// Skip if we already recorded this device
		if seen[ip] {
			continue
		}

		seen[ip] = true
		devices = append(devices, Device{
			IP:  ip,
			MAC: packet.SenderHardwareAddr.String(),
		})
	}

	return devices, nil
}

// incrementIP is no longer needed - netip.Addr has a built-in Next() method
// cloneIP is no longer needed - netip.Addr is a value type, not a slice