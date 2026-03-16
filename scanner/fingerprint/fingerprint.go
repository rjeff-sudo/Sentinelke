package fingerprint

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Banner holds what we learned from connecting to an open port
type Banner struct {
	Port    int
	Raw     string // the raw text the service sent back
	Service string // interpreted service name
	Version string // version if we could extract it
	Risk    string // "LOW", "MEDIUM", "HIGH"
	Note    string // plain english explanation
}

// GrabBanner connects to a host:port and reads the greeting the service sends
func GrabBanner(host string, port int, timeout time.Duration) Banner {
	banner := Banner{Port: port}

	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return banner
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	reader := bufio.NewReader(conn)

	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)

	var lines []string
	for i := 0; i < 5; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Clean each line before joining
	for i, line := range lines {
		lines[i] = cleanBanner(line)
	}

	// Filter out any lines that became empty after cleaning
	var cleaned []string
	for _, line := range lines {
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}

	if len(cleaned) > 0 {
		banner.Raw = strings.Join(cleaned, " | ")
	}

	banner.Service, banner.Version = parseService(port, cleaned)

	// Always assess risk even if banner was empty - port number alone is enough
	banner.Risk, banner.Note = assessRisk(port, banner.Service, banner.Version)

	return banner
}

// GrabBannerTLS does the same but wraps the connection in TLS
func GrabBannerTLS(host string, port int, timeout time.Duration) Banner {
	banner := Banner{Port: port}

	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		address,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return banner
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))

	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)

	reader := bufio.NewReader(conn)
	var lines []string
	for i := 0; i < 5; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}

	// Extract TLS certificate info
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		certInfo := fmt.Sprintf("TLS-CN:%s EXPIRES:%s",
			cert.Subject.CommonName,
			cert.NotAfter.Format("2006-01-02"),
		)
		lines = append(lines, certInfo)
	}

	// Clean each line before joining
	for i, line := range lines {
		lines[i] = cleanBanner(line)
	}

	// Filter out any lines that became empty after cleaning
	var cleaned []string
	for _, line := range lines {
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}

	if len(cleaned) > 0 {
		banner.Raw = strings.Join(cleaned, " | ")
	}

	banner.Service, banner.Version = parseService(port, cleaned)

	// Always assess risk even if banner was empty - port number alone is enough
	banner.Risk, banner.Note = assessRisk(port, banner.Service, banner.Version)

	return banner
}

// parseService looks at the port number and banner text to identify
// the service and extract a version string if possible
func parseService(port int, lines []string) (service, version string) {
	combined := strings.ToLower(strings.Join(lines, " "))

	switch {
	case port == 22 || strings.Contains(combined, "ssh"):
		service = "SSH"
		version = extractVersion(lines, "SSH-")

	case port == 21 || strings.Contains(combined, "ftp"):
		service = "FTP"
		version = extractVersion(lines, "220")

	case port == 23:
		service = "Telnet"

	case port == 25 || strings.Contains(combined, "smtp"):
		service = "SMTP"
		version = extractVersion(lines, "220")

	case port == 80 || port == 8080 || strings.Contains(combined, "http"):
		service = "HTTP"
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				version = strings.TrimSpace(line[7:])
			}
		}

	case port == 443 || port == 8443:
		service = "HTTPS"
		for _, line := range lines {
			if strings.HasPrefix(strings.ToLower(line), "server:") {
				version = strings.TrimSpace(line[7:])
			}
		}

	case port == 3306 || strings.Contains(combined, "mysql"):
		service = "MySQL"
		version = extractVersion(lines, "")

	case port == 5432:
		service = "PostgreSQL"

	case port == 6379 || strings.Contains(combined, "redis"):
		service = "Redis"

	case port == 53:
		service = "DNS"

	case port == 88:
		service = "Kerberos"

	default:
		service = "Unknown"
	}

	return service, version
}

// extractVersion scans banner lines for a version string starting with prefix
func extractVersion(lines []string, prefix string) string {
	for _, line := range lines {
		if prefix == "" || strings.Contains(line, prefix) {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.Contains(p, ".") {
					return strings.TrimRight(p, ");,")
				}
			}
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// cleanBanner removes non-printable and control characters from banner text
// Telnet and some other protocols send binary negotiation bytes
// that garbage up the output
func cleanBanner(s string) string {
	var result strings.Builder
	for _, r := range s {
		// Keep only printable ASCII characters
		if r >= 32 && r < 127 {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

// assessRisk takes the service and version and returns a risk level
// and a plain-English note
func assessRisk(port int, service, version string) (risk, note string) {
	switch service {
	case "Telnet":
		return "HIGH", "Telnet transmits all data including passwords in plain text. Disable immediately."

	case "FTP":
		return "HIGH", "FTP sends credentials and files unencrypted. Use SFTP instead."

	case "SSH":
		if version != "" && strings.Contains(version, "1.") {
			return "HIGH", "SSH version 1 is obsolete and has known vulnerabilities. Upgrade to SSH v2."
		}
		return "LOW", "SSH is encrypted. Ensure password authentication is disabled and keys are used."

	case "HTTP":
		return "MEDIUM", "Unencrypted web traffic. Any data submitted through this service can be intercepted."

	case "HTTPS":
		return "LOW", "Encrypted web traffic. Verify certificate expiry and configuration."

	case "MySQL":
		return "HIGH", "Database port exposed on network. Restrict to localhost or trusted IPs only."

	case "Redis":
		return "HIGH", "Redis has no authentication by default. If exposed, your data is publicly readable."

	case "DNS":
		return "LOW", "DNS resolver open. Ensure it only responds to your internal network, not the public internet."

	default:
		return "LOW", fmt.Sprintf("Service on port %d. Verify this port should be open.", port)
	}
}