package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type TCPConnectEngine struct {
	timeout     time.Duration
	concurrency int
}

func NewTCPConnectEngine() *TCPConnectEngine {
	return &TCPConnectEngine{timeout: 1500 * time.Millisecond, concurrency: 256}
}

func (engine *TCPConnectEngine) Name() string { return "tcp-connect" }

func (engine *TCPConnectEngine) ScanPorts(ctx context.Context, targets []string, ports []int) ([]*PortScanResult, error) {
	targets = uniqueTargets(targets)
	ports = uniquePorts(ports)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid scan targets")
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports")
	}

	type job struct {
		target string
		port   int
	}
	jobs := make(chan job, engine.concurrency)
	results := make(chan *PortScanResult, engine.concurrency)
	workerCount := engine.concurrency
	if total := len(targets) * len(ports); workerCount > total {
		workerCount = total
	}

	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			dialer := net.Dialer{Timeout: engine.timeout}
			for task := range jobs {
				connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(task.target, fmt.Sprintf("%d", task.port)))
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					continue
				}
				_ = connection.Close()
				select {
				case results <- &PortScanResult{IP: task.target, Port: task.port, Protocol: "tcp", Open: true, Service: "unknown"}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, target := range targets {
			for _, port := range ports {
				select {
				case jobs <- job{target: target, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()

	openPorts := make([]*PortScanResult, 0)
	for result := range results {
		openPorts = append(openPorts, result)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(openPorts, func(i, j int) bool {
		if openPorts[i].IP == openPorts[j].IP {
			return openPorts[i].Port < openPorts[j].Port
		}
		return openPorts[i].IP < openPorts[j].IP
	})
	if len(openPorts) > 0 {
		openPorts = NewServiceDetector().DetectServices(openPorts)
	}
	return openPorts, nil
}

func uniqueTargets(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if net.ParseIP(value) != nil && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func uniquePorts(values []int) []int {
	seen := make(map[int]bool, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if value >= 1 && value <= 65535 && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Ints(result)
	return result
}
