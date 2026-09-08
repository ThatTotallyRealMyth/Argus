package scanner

// ProgressHandler Scan Progress Processor Interface
// By WebSocket handler Achieved, TaskService To push progress updates through this interface
type ProgressHandler interface {
	// RegisterProgressChannel Progress Channel for Register Tasks
	RegisterProgressChannel(taskID string, ch chan *ScanProgress)

	// UnregisterProgressChannel Progress trail for write-off tasks
	UnregisterProgressChannel(taskID string)

	// BroadcastProgress Radio Simple Progress Updates to All Subscription Clients
	BroadcastProgress(taskID string, progress int, message string)

	// BroadcastTaskComplete Broadcasting Mission End, Driver client refresh final result.
	BroadcastTaskComplete(taskID string, status string, message string)
}
