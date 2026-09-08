package utils

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// GenerateID Generate RandomID
func GenerateID(prefix string) string {
	timestamp := time.Now().Unix()
	random := rand.Intn(100000)
	return fmt.Sprintf("%s_%d_%d", prefix, timestamp, random)
}

// MD5Hash CalculateMD5Hashi.
func MD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

// SHA256Hash CalculateSHA256Hashi.
func SHA256Hash(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

// IsPrivateIP To judge whether it's an intranet.IP
func IsPrivateIP(ip string) bool {
	// 10.0.0.0/8
	if strings.HasPrefix(ip, "10.") {
		return true
	}
	// 172.16.0.0/12
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			second := parts[1]
			if second >= "16" && second <= "31" {
				return true
			}
		}
	}
	// 192.168.0.0/16
	if strings.HasPrefix(ip, "192.168.") {
		return true
	}
	// 127.0.0.0/8
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	return false
}

// SanitizeFilename Clear File Name
func SanitizeFilename(filename string) string {
	// Remove unsafe characters
	unsafe := []string{"..", "/", "\\", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range unsafe {
		filename = strings.ReplaceAll(filename, char, "_")
	}
	return filename
}

// TruncateString Cut String
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// Contains Check if the slice contains elements
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates Remove duplicate elements
func RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, exists := keys[entry]; !exists {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// ParseTarget Parsing target
func ParseTarget(target string) ([]string, error) {
	return ParseTargetContext(context.Background(), target)
}

// ParseTargetContext parses a target and expands CIDR ranges when requested.
func ParseTargetContext(ctx context.Context, target string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	targets := strings.Split(target, ",")
	result := make([]string, 0, len(targets))

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		if expanded, matched, err := expandCIDRTargetContext(ctx, t); matched {
			if err != nil {
				return nil, err
			}
			result = append(result, expanded...)
			continue
		}
		result = append(result, t)
	}

	return result, nil
}

const maxExpandedCIDRHosts = 1 << 16

func expandCIDRTarget(target string) ([]string, bool, error) {
	return expandCIDRTargetContext(context.Background(), target)
}

func expandCIDRTargetContext(ctx context.Context, target string) ([]string, bool, error) {
	if strings.Contains(target, "://") || !strings.Contains(target, "/") {
		return nil, false, nil
	}
	prefix := strings.SplitN(target, "/", 2)[0]
	if net.ParseIP(prefix) == nil {
		return nil, false, nil
	}
	ip, network, err := net.ParseCIDR(target)
	if err != nil {
		return nil, true, fmt.Errorf("invalid CIDR target %q: %w", target, err)
	}
	ones, bits := network.Mask.Size()
	if ones < 0 || bits-ones > 16 {
		return nil, true, fmt.Errorf("CIDR target %q exceeds the %d host expansion limit", target, maxExpandedCIDRHosts)
	}
	count := 1 << uint(bits-ones)
	if count > maxExpandedCIDRHosts {
		return nil, true, fmt.Errorf("CIDR target %q exceeds the %d host expansion limit", target, maxExpandedCIDRHosts)
	}
	base := ip.Mask(network.Mask)
	result := make([]string, 0, count)
	current := append(net.IP(nil), base...)
	for index := 0; index < count; index++ {
		select {
		case <-ctx.Done():
			return nil, true, ctx.Err()
		default:
		}
		result = append(result, current.String())
		incrementIP(current)
	}
	return result, true, nil
}

func incrementIP(ip net.IP) {
	for index := len(ip) - 1; index >= 0; index-- {
		ip[index]++
		if ip[index] != 0 {
			return
		}
	}
}

// FormatDuration Format Time Interval
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fsec", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fmin", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fHours", d.Hours())
	}
	return fmt.Sprintf("%.1fJesus.", d.Hours()/24)
}

// GeneratePassword Generate Random Password
func GeneratePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
	rand.Seed(time.Now().UnixNano())

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// IsValidDomain Authenticate domain name format
func IsValidDomain(domain string) bool {
	if domain == "" || len(domain) > 255 {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if strings.Contains(domain, " ") {
		return false
	}
	return true
}

// IsValidIP AuthenticationIPFormat
func IsValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		// Simple Authentication, It should actually be more rigorous.
	}
	return true
}

// ChunkSlice Split Slicing
func ChunkSlice(slice []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

// MergeMap Mergemap
func MergeMap(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}
