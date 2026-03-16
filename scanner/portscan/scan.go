package portscan

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Result holds the outcome of scanning a single port
type Result struct {
	Port    int
	Open    bool
	Service string // e.g. "SSH", "HTTP", "MySQL"
}

// knownPorts maps common port numbers to their service names
var knownPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	88:   "Kerberos",
	110:  "POP3",
	143:  "IMAP",
	389:  "LDAP",
	443:  "HTTPS",
	445:  "SMB",
	587:  "SMTP-TLS",
	631:  "IPP-Printing",
	993:  "IMAPS",
	995:  "POP3S",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
	6379: "Redis",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
	9200: "Elasticsearch",
}
// ScanPort checks if a single TCP port is open on a host
func ScanPort(host string, port int, timeout time.Duration) Result {
	address := fmt.Sprintf("%s:%d", host, port)

	// net.DialTimeout attempts a TCP connection
	// If it succeeds - port is open
	// If it times out or is refused - port is closed
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return Result{Port: port, Open: false}
	}
	conn.Close() // connection succeeded, close it immediately

	// Look up the service name for this port
	service := knownPorts[port]
	if service == "" {
		service = "Unknown"
	}

	return Result{Port: port, Open: true, Service: service}
}

// ScanHost scans a range of ports on a host concurrently using goroutines
// startPort and endPort define the range e.g. 1 to 1024
func ScanHost(host string, startPort, endPort int, timeout time.Duration) []Result {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex // protects the results slice
		results []Result
	)

	// Semaphore channel - limits how many goroutines run at once
	// Without this, scanning 65535 ports would spawn 65535 goroutines simultaneously
	sem := make(chan struct{}, 100) // max 100 concurrent scans

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{} // acquire a slot

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }() // release the slot when done

			result := ScanPort(host, p, timeout)

			if result.Open {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait() // block until all goroutines finish

	// Sort results by port number for clean output
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}