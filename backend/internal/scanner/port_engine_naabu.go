//go:build linux && cgo

package scanner

func NewPortScanEngine() PortScanEngine { return NewNaabuEngine() }
