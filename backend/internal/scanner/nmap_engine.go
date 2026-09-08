package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// NmapEngine performs accuracy-focused TCP connect and service-version scans.
// TCP connect scanning works in the unprivileged production container, while
// -Pn ensures that hosts are not discarded merely because discovery probes are
// filtered. The existing task port selection is passed through unchanged.
type NmapEngine struct {
	binary string
}

func NewNmapEngine() *NmapEngine {
	return &NmapEngine{binary: "nmap"}
}

func (engine *NmapEngine) Name() string { return "nmap" }

func (engine *NmapEngine) ScanPorts(ctx context.Context, targets []string, ports []int) ([]*PortScanResult, error) {
	if len(targets) == 0 || len(ports) == 0 {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := exec.LookPath(engine.binary); err != nil {
		return nil, fmt.Errorf("nmap is not installed or not available in PATH: %w", err)
	}

	portSpec, err := compactNmapPorts(ports)
	if err != nil {
		return nil, err
	}
	targetFile, err := writeNmapTargets(targets)
	if err != nil {
		return nil, err
	}
	defer os.Remove(targetFile)

	args := []string{
		"-Pn",
		"-sT",
		"-sV",
		"--version-all",
		"-T3",
		"--max-retries", "3",
		"--reason",
		"--open",
		"-n",
		"-oX", "-",
		"-iL", targetFile,
		"-p", portSpec,
	}

	command := exec.CommandContext(ctx, engine.binary, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("create nmap output pipe: %w", err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start nmap: %w", err)
	}

	results, parseErr := parseNmapXML(stdout)
	if parseErr != nil && command.Process != nil {
		_ = command.Process.Kill()
	}
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if waitErr != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("nmap failed: %w: %s", waitErr, message)
		}
		return nil, fmt.Errorf("nmap failed: %w", waitErr)
	}
	if parseErr != nil {
		return nil, fmt.Errorf("parse nmap XML: %w", parseErr)
	}
	return results, nil
}

func writeNmapTargets(targets []string) (string, error) {
	file, err := os.CreateTemp("", "argus-nmap-targets-*.txt")
	if err != nil {
		return "", fmt.Errorf("create nmap target file: %w", err)
	}
	path := file.Name()
	removeOnError := true
	defer func() {
		_ = file.Close()
		if removeOnError {
			_ = os.Remove(path)
		}
	}()

	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure nmap target file: %w", err)
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		normalized := strings.TrimSpace(target)
		if net.ParseIP(normalized) == nil {
			return "", fmt.Errorf("invalid nmap IP target %q", target)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		if _, err := fmt.Fprintln(file, normalized); err != nil {
			return "", fmt.Errorf("write nmap target file: %w", err)
		}
	}
	if len(seen) == 0 {
		return "", errors.New("no valid nmap targets supplied")
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close nmap target file: %w", err)
	}
	removeOnError = false
	return path, nil
}

func compactNmapPorts(ports []int) (string, error) {
	unique := make(map[int]struct{}, len(ports))
	ordered := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid TCP port %d", port)
		}
		if _, exists := unique[port]; exists {
			continue
		}
		unique[port] = struct{}{}
		ordered = append(ordered, port)
	}
	if len(ordered) == 0 {
		return "", errors.New("no TCP ports supplied")
	}
	sort.Ints(ordered)

	parts := make([]string, 0, len(ordered))
	for startIndex := 0; startIndex < len(ordered); {
		endIndex := startIndex
		for endIndex+1 < len(ordered) && ordered[endIndex+1] == ordered[endIndex]+1 {
			endIndex++
		}
		if startIndex == endIndex {
			parts = append(parts, strconv.Itoa(ordered[startIndex]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ordered[startIndex], ordered[endIndex]))
		}
		startIndex = endIndex + 1
	}
	return strings.Join(parts, ","), nil
}

type nmapXMLHost struct {
	Addresses []struct {
		Address string `xml:"addr,attr"`
		Type    string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		ID       int    `xml:"portid,attr"`
		State    struct {
			Value string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name      string `xml:"name,attr"`
			Product   string `xml:"product,attr"`
			Version   string `xml:"version,attr"`
			ExtraInfo string `xml:"extrainfo,attr"`
			Tunnel    string `xml:"tunnel,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

func parseNmapXML(reader io.Reader) ([]*PortScanResult, error) {
	decoder := xml.NewDecoder(reader)
	results := make([]*PortScanResult, 0)
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return results, nil
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "host" {
			continue
		}
		var host nmapXMLHost
		if err := decoder.DecodeElement(&host, &start); err != nil {
			return nil, err
		}
		address := nmapHostAddress(host)
		if address == "" {
			continue
		}
		for _, port := range host.Ports {
			if port.State.Value != "open" {
				continue
			}
			service := strings.TrimSpace(port.Service.Name)
			if service == "" {
				service = "unknown"
			}
			if strings.EqualFold(port.Service.Tunnel, "ssl") {
				if strings.EqualFold(service, "http") {
					service = "https"
				} else {
					service = "ssl/" + service
				}
			}
			bannerParts := make([]string, 0, 3)
			for _, part := range []string{port.Service.Product, port.Service.Version, port.Service.ExtraInfo} {
				if value := strings.TrimSpace(part); value != "" {
					bannerParts = append(bannerParts, value)
				}
			}
			results = append(results, &PortScanResult{
				IP:       address,
				Port:     port.ID,
				Protocol: port.Protocol,
				Open:     true,
				Service:  service,
				Version:  strings.TrimSpace(port.Service.Version),
				Product:  strings.TrimSpace(port.Service.Product),
				Banner:   strings.Join(bannerParts, " "),
			})
		}
	}
}

func nmapHostAddress(host nmapXMLHost) string {
	for _, address := range host.Addresses {
		if address.Type == "ipv4" || address.Type == "ipv6" {
			return address.Address
		}
	}
	return ""
}
