package handlers

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/reconmaster/backend/internal/logger"
	"github.com/reconmaster/backend/internal/scanner"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源（生产环境应该限制）
	},
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: 10 * time.Second,
}

const (
	// 客户端写入超时
	writeWait = 10 * time.Second
	// 客户端 pong 超时 - 如果在这个时间内没有收到 pong，则断开连接
	pongWait = 60 * time.Second
	// ping 发送间隔 - 服务器发送 ping 的间隔（必须小于 pongWait）
	pingPeriod = 25 * time.Second
	// 最大消息大小 (增加到 4KB，足够处理进度消息)
	maxMessageSize = 4096
)

// WebSocketHandler WebSocket处理器
type WebSocketHandler struct {
	clients       map[*websocket.Conn]*webSocketClient
	clientsMutex  sync.RWMutex
	progressChans map[string]chan *scanner.ScanProgress // taskID -> progress channel
	chansMutex    sync.RWMutex
}

type webSocketClient struct {
	conn    *websocket.Conn
	taskID  string
	writeMu sync.Mutex
	closed  bool
}

func (client *webSocketClient) writeJSON(value any) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if client.closed {
		return websocket.ErrCloseSent
	}
	client.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return client.conn.WriteJSON(value)
}

func (client *webSocketClient) writeMessage(messageType int, data []byte) error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if client.closed {
		return websocket.ErrCloseSent
	}
	client.conn.SetWriteDeadline(time.Now().Add(writeWait))
	return client.conn.WriteMessage(messageType, data)
}

func (client *webSocketClient) close() error {
	client.writeMu.Lock()
	defer client.writeMu.Unlock()
	if client.closed {
		return nil
	}
	client.closed = true
	return client.conn.Close()
}

// NewWebSocketHandler 创建WebSocket处理器
func NewWebSocketHandler() *WebSocketHandler {
	handler := &WebSocketHandler{
		clients:       make(map[*websocket.Conn]*webSocketClient),
		progressChans: make(map[string]chan *scanner.ScanProgress),
	}

	// 启动进度分发器
	go handler.progressDispatcher()

	return handler
}

// HandleWebSocket 处理WebSocket连接
func (h *WebSocketHandler) HandleWebSocket(c *gin.Context) {
	taskID := c.Query("task_id")
	if taskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task_id is required"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.Error("WebSocket upgrade failed: %v", err)
		return
	}

	client := &webSocketClient{conn: conn, taskID: taskID}

	// 注册客户端
	h.clientsMutex.Lock()
	h.clients[conn] = client
	h.clientsMutex.Unlock()

	// 只在生产环境中减少日志
	// log.Printf("WebSocket client connected for task: %s", taskID)

	// 配置连接参数
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// 发送欢迎消息
	welcomeMsg := map[string]interface{}{
		"type":    "connected",
		"task_id": taskID,
		"message": "WebSocket connected successfully",
		"time":    time.Now().Format(time.RFC3339),
	}
	if err := client.writeJSON(welcomeMsg); err != nil {
		logger.Error("Failed to send welcome message: %v", err)
		h.removeClient(client)
		return
	}

	// 启动心跳 goroutine
	done := make(chan struct{})
	go h.writePump(client, done)

	// 读取客户端消息（会在结束时通过 defer 关闭 done channel）
	h.readPump(conn, taskID, done)

	// 清理（readPump 已经通过 defer 关闭了 done）
	h.removeClient(client)

	// 只在生产环境中减少日志
	// log.Printf("WebSocket client disconnected for task: %s", taskID)
}

// readPump 处理从客户端读取消息
func (h *WebSocketHandler) readPump(conn *websocket.Conn, taskID string, done chan struct{}) {
	defer func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}()

	conn.SetReadLimit(maxMessageSize)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		select {
		case <-done:
			return
		default:
		}

		// 移出 select，直接读取消息（避免阻塞）
		_, message, err := conn.ReadMessage()
		if err != nil {
			// 只记录真正意外的关闭，正常关闭码（1000, 1001, 1005）不记录
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseNormalClosure,      // 1000 - 正常关闭
				websocket.CloseGoingAway,          // 1001 - 客户端离开
				websocket.CloseNoStatusReceived) { // 1005 - 无状态关闭
				logger.Error("WebSocket unexpected close for task %s: %v", taskID, err)
			}
			// 正常关闭不记录日志，保持安静
			return
		}

		// 处理客户端消息
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err == nil {
			if msgType, ok := msg["type"].(string); ok {
				switch msgType {
				case "ping":
					// log.Printf("Received ping from task: %s", taskID) // 减少噪音
				case "pong":
					// 客户端响应pong
					conn.SetReadDeadline(time.Now().Add(pongWait))
				}
			}
		}
	}
}

// writePump 处理向客户端发送心跳
func (h *WebSocketHandler) writePump(client *webSocketClient, done chan struct{}) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := client.writeMessage(websocket.PingMessage, nil); err != nil {
				logger.Error("Failed to send ping to task %s: %v", client.taskID, err)
				return
			}
		}
	}
}

func (h *WebSocketHandler) removeClient(client *webSocketClient) {
	if client == nil {
		return
	}
	h.clientsMutex.Lock()
	delete(h.clients, client.conn)
	h.clientsMutex.Unlock()
	_ = client.close()
}

func (h *WebSocketHandler) clientsForTask(taskID string) []*webSocketClient {
	h.clientsMutex.RLock()
	defer h.clientsMutex.RUnlock()
	clients := make([]*webSocketClient, 0)
	for _, client := range h.clients {
		if client.taskID == taskID {
			clients = append(clients, client)
		}
	}
	return clients
}

// RegisterProgressChannel 注册任务的进度通道
func (h *WebSocketHandler) RegisterProgressChannel(taskID string, ch chan *scanner.ScanProgress) {
	h.chansMutex.Lock()
	h.progressChans[taskID] = ch
	h.chansMutex.Unlock()
	// log.Printf("Progress channel registered for task: %s", taskID) // 减少日志
}

// UnregisterProgressChannel 注销任务的进度通道
func (h *WebSocketHandler) UnregisterProgressChannel(taskID string) {
	h.chansMutex.Lock()
	if ch, exists := h.progressChans[taskID]; exists {
		close(ch)
		delete(h.progressChans, taskID)
	}
	h.chansMutex.Unlock()
	// log.Printf("Progress channel unregistered for task: %s", taskID) // 减少日志
}

// progressDispatcher 进度分发器 - 从进度通道读取并广播给WebSocket客户端
func (h *WebSocketHandler) progressDispatcher() {
	ticker := time.NewTicker(100 * time.Millisecond) // 每100ms检查一次
	defer ticker.Stop()

	for range ticker.C {
		h.chansMutex.RLock()
		for taskID, progressChan := range h.progressChans {
			// 非阻塞读取进度
			select {
			case progress, ok := <-progressChan:
				if !ok {
					// 通道已关闭
					continue
				}
				// 广播进度到所有订阅该任务的客户端
				h.broadcastProgress(taskID, progress)
			default:
				// 没有新进度，跳过
			}
		}
		h.chansMutex.RUnlock()
	}
}

// broadcastProgress 广播进度到指定任务的所有客户端
func (h *WebSocketHandler) broadcastProgress(taskID string, progress *scanner.ScanProgress) {
	message := map[string]interface{}{
		"type":         "progress",
		"task_id":      taskID,
		"stage":        progress.Stage,
		"current":      progress.Current,
		"total":        progress.Total,
		"percentage":   progress.Percentage,
		"speed":        progress.Speed,
		"open_ports":   progress.OpenPorts,
		"elapsed_time": progress.ElapsedTime,
		"eta":          progress.ETA,
		"message":      progress.Message,
		"timestamp":    progress.Timestamp.Format(time.RFC3339),
	}

	for _, client := range h.clientsForTask(taskID) {
		if err := client.writeJSON(message); err != nil {
			logger.Error("Failed to send progress to client: %v", err)
		}
	}
}

// BroadcastProgress 广播简易进度更新（实现 scanner.ProgressHandler 接口）
func (h *WebSocketHandler) BroadcastProgress(taskID string, progress int, message string) {
	msg := map[string]interface{}{
		"type":     "progress",
		"task_id":  taskID,
		"progress": progress,
		"message":  message,
		"time":     time.Now().Format(time.RFC3339),
	}

	for _, client := range h.clientsForTask(taskID) {
		if err := client.writeJSON(msg); err != nil {
			logger.Error("Failed to send progress: %v", err)
		}
	}
}

// BroadcastTaskComplete 广播任务完成消息
func (h *WebSocketHandler) BroadcastTaskComplete(taskID string, status string, message string) {
	completeMsg := map[string]interface{}{
		"type":    "task_complete",
		"task_id": taskID,
		"status":  status,
		"message": message,
		"time":    time.Now().Format(time.RFC3339),
	}

	for _, client := range h.clientsForTask(taskID) {
		if err := client.writeJSON(completeMsg); err != nil {
			logger.Error("Failed to send task complete message: %v", err)
		}
	}
}

// GetProgressChannel 获取或创建任务的进度通道
func (h *WebSocketHandler) GetProgressChannel(taskID string) chan *scanner.ScanProgress {
	h.chansMutex.Lock()
	defer h.chansMutex.Unlock()

	if ch, exists := h.progressChans[taskID]; exists {
		return ch
	}

	ch := make(chan *scanner.ScanProgress, 100)
	h.progressChans[taskID] = ch
	return ch
}
