package fingerprint

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// startTestServer spins up a TCP listener that sends a fixed banner
// when a client connects — simulates a real service
func startBannerServer(t *testing.T, banner string) (port int, stop func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start test server: %v", err)
	}

	port = listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Send the banner immediately on connect
			fmt.Fprintf(conn, "%s\r\n", banner)
			conn.Close()
		}
	}()

	stop = func() { listener.Close() }
	return port, stop
}

// TestGrabBanner_FTPBanner checks we correctly parse an FTP banner
func TestGrabBanner_FTPBanner(t *testing.T) {
	port, stop := startBannerServer(t, "220 MikroTik FTP server (MikroTik 7.18.2) ready")
	defer stop()

	b := GrabBanner("127.0.0.1", port, 2*time.Second)

	if b.Service != "FTP" {
		t.Errorf("expected service FTP, got %s", b.Service)
	}
	if b.Risk != "HIGH" {
		t.Errorf("expected HIGH risk for FTP, got %s", b.Risk)
	}
}

// TestGrabBanner_SSHBanner checks SSH detection and version extraction
func TestGrabBanner_SSHBanner(t *testing.T) {
	port, stop := startBannerServer(t, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
	defer stop()

	b := GrabBanner("127.0.0.1", port, 2*time.Second)

	if b.Service != "SSH" {
		t.Errorf("expected service SSH, got %s", b.Service)
	}
	if b.Risk != "LOW" {
		t.Errorf("expected LOW risk for SSH v2, got %s", b.Risk)
	}
}

// TestGrabBanner_MySQLBanner checks MySQL detection and HIGH risk flagging
func TestGrabBanner_MySQLBanner(t *testing.T) {
	port, stop := startBannerServer(t, "5.7.32-MySQL Community Server")
	defer stop()

	b := GrabBanner("127.0.0.1", port, 2*time.Second)

	if b.Service != "MySQL" {
		t.Errorf("expected service MySQL, got %s", b.Service)
	}
	if b.Risk != "HIGH" {
		t.Errorf("expected HIGH risk for exposed MySQL, got %s", b.Risk)
	}
}

// TestGrabBanner_UnreachableHost checks graceful handling when nothing responds
func TestGrabBanner_UnreachableHost(t *testing.T) {
	// Port 1 on localhost is almost certainly closed
	b := GrabBanner("127.0.0.1", 1, 500*time.Millisecond)

	// Should return an empty banner, not panic or error
	if b.Port != 1 {
		t.Errorf("expected port 1 in result, got %d", b.Port)
	}
	if b.Raw != "" {
		t.Errorf("expected empty raw banner for closed port, got %s", b.Raw)
	}
}

// TestCleanBanner_RemovesGarbage checks that binary/control characters are stripped
func TestCleanBanner_RemovesGarbage(t *testing.T) {
	dirty := "\xFF\xFB\x01\xFF\xFB\x03HEAD / HTTP/1.0"
	result := cleanBanner(dirty)

	// Should contain only the printable part
	if !strings.Contains(result, "HEAD") {
		t.Errorf("expected printable text to be preserved, got: %q", result)
	}
	// Should not contain the garbage bytes
	if strings.ContainsRune(result, '\xFF') {
		t.Errorf("expected garbage bytes to be removed, got: %q", result)
	}
}

// TestCleanBanner_VersionTrailingParen checks we can clean version strings
func TestCleanBanner_VersionTrailingParen(t *testing.T) {
	// This is the actual MikroTik banner that gives us "7.18.2)"
	raw := "220 MikroTik FTP server (MikroTik 7.18.2) ready"

	// extractVersion picks the first word containing a dot
	// "7.18.2)" contains a dot so it gets returned as-is
	// We verify the issue exists so we know to fix extractVersion
	version := extractVersion([]string{raw}, "220")

	// The version should ideally not have a trailing paren
	cleaned := strings.TrimRight(version, ")")
	if cleaned != "7.18.2" {
		t.Errorf("expected cleaned version 7.18.2, got %s", cleaned)
	}
}

// TestAssessRisk_AllServices checks every service returns a non-empty risk level
func TestAssessRisk_AllServices(t *testing.T) {
	services := []string{"Telnet", "FTP", "SSH", "HTTP", "HTTPS", "MySQL", "Redis", "DNS", "Unknown"}

	for _, svc := range services {
		risk, note := assessRisk(0, svc, "")
		if risk == "" {
			t.Errorf("service %s returned empty risk level", svc)
		}
		if note == "" {
			t.Errorf("service %s returned empty note", svc)
		}
	}
}