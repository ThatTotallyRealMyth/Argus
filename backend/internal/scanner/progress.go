package scanner

// ProgressHandler 扫描进度处理器接口
// 由 WebSocket handler 实现，TaskService 通过此接口推送进度更新
type ProgressHandler interface {
	// RegisterProgressChannel 注册任务的进度通道
	RegisterProgressChannel(taskID string, ch chan *ScanProgress)

	// UnregisterProgressChannel 注销任务的进度通道
	UnregisterProgressChannel(taskID string)

	// BroadcastProgress 广播简易进度更新到所有订阅客户端
	BroadcastProgress(taskID string, progress int, message string)

	// BroadcastTaskComplete 广播任务终态，驱动客户端刷新最终结果。
	BroadcastTaskComplete(taskID string, status string, message string)
}
