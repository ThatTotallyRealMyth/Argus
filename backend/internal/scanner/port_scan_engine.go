package scanner

import "context"

type PortScanEngine interface {
	Name() string
	ScanPorts(ctx context.Context, targets []string, ports []int) ([]*PortScanResult, error)
}
