package portscan

import (
	"net"
	"testing"
	"time"
)

// startTestServer spins up a real TCP listener on a random port
// This gives us a real open port to test against - no mocking needed
func startTestServer(t *testing.T) (port int, stop func()) {
	t.Helper()

	// Listen on port 0 - the OS assigns a free port automatically
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start test server: %v", err)
	}

	// Extract the port the OS assigned
	port = listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background so ScanPort doesn't hang
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener was closed, exit goroutine
			}
			conn.Close()
		}
	}()

	// Return a stop function the test can call to shut down
	stop = func() { listener.Close() }
	return port, stop
}

// TestScanPort_OpenPort checks that ScanPort correctly detects an open port
func TestScanPort_OpenPort(t *testing.T) {
	port, stop := startTestServer(t)
	defer stop()

	result := ScanPort("127.0.0.1", port, 1*time.Second)

	if !result.Open {
		t.Errorf("expected port %d to be open, but got closed", port)
	}
	if result.Port != port {
		t.Errorf("expected port %d in result, got %d", port, result.Port)
	}
}

// TestScanPort_ClosedPort checks that ScanPort correctly detects a closed port
func TestScanPort_ClosedPort(t *testing.T) {
	// Port 1 is almost never open and requires no privileges to check
	result := ScanPort("127.0.0.1", 1, 500*time.Millisecond)

	if result.Open {
		t.Errorf("expected port 1 to be closed, but got open")
	}
}

// TestScanPort_KnownService checks that recognised ports get labelled correctly
func TestScanPort_KnownService(t *testing.T) {
	// We need an actual open port to get a result with a service name
	// So we listen on a fixed port that matches a known service
	// Port 8080 = HTTP-Alt in our knownPorts map
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Skip("port 8080 already in use, skipping service label test")
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	result := ScanPort("127.0.0.1", 8080, 1*time.Second)

	if !result.Open {
		t.Fatal("expected port 8080 to be open")
	}
	if result.Service != "HTTP-Alt" {
		t.Errorf("expected service 'HTTP-Alt', got '%s'", result.Service)
	}
}

// TestScanHost_ReturnsOpenPorts checks that ScanHost finds all open ports
// in a range and returns them sorted
func TestScanHost_ReturnsOpenPorts(t *testing.T) {
	// Start two test servers on random ports
	port1, stop1 := startTestServer(t)
	defer stop1()
	port2, stop2 := startTestServer(t)
	defer stop2()

	// Scan the full range 1-65535 would be slow in tests
	// Instead scan just around our known open ports
	low := min(port1, port2) - 1
	high := max(port1, port2) + 1

	results := ScanHost("127.0.0.1", low, high, 500*time.Millisecond)

	if len(results) < 2 {
		t.Errorf("expected at least 2 open ports, got %d", len(results))
	}

	// Verify results are sorted by port number
	for i := 1; i < len(results); i++ {
		if results[i].Port < results[i-1].Port {
			t.Errorf("results not sorted: port %d came before %d",
				results[i-1].Port, results[i].Port)
		}
	}
}

// min and max helpers (Go 1.21+ has these built in, adding for clarity)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}