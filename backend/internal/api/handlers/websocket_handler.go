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
		return true // Allow All Sources (The production environment should be limited.)
	},
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
	HandshakeTimeout: 10 * time.Second,
}

const (
	// Client Write Timeout
	writeWait = 10 * time.Second
	// Client pong Timeout - If you don't get it in that time, pong, Disconnect
	pongWait = 60 * time.Second
	// ping Send Interval - Server Send ping Intervals (must be less than pongWait)
	pingPeriod = 25 * time.Second
	// Maximum message size (Increase to 4KB, Enough to process progress information)
	maxMessageSize = 4096
)

// WebSocketHandler WebSocketProcessor
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

// NewWebSocketHandler CreateWebSocketProcessor
func NewWebSocketHandler() *WebSocketHandler {
	handler := &WebSocketHandler{
		clients:       make(map[*websocket.Conn]*webSocketClient),
		progressChans: make(map[string]chan *scanner.ScanProgress),
	}

	// Start progress distributor
	go handler.progressDispatcher()

	return handler
}

// HandleWebSocket ProcessingWebSocketConnection
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

	// Register Client
	h.clientsMutex.Lock()
	h.clients[conn] = client
	h.clientsMutex.Unlock()

	// Only in production environments
	// log.Printf("WebSocket client connected for task: %s", taskID)

	// Configure connection parameters
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	// Send Welcome Message
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

	// Start the heartbeat. goroutine
	done := make(chan struct{})
	go h.writePump(client, done)

	// Read Client Messages (It'll pass at the end. defer Close done channel)
	h.readPump(conn, taskID, done)

	// Clean (readPump Passed defer It's closed. done)
	h.removeClient(client)

	// Only in production environments
	// log.Printf("WebSocket client disconnected for task: %s", taskID)
}

// readPump Process reading from client
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

		// Move Out select, Read Messages Directly (Avoid blocking)
		_, message, err := conn.ReadMessage()
		if err != nil {
			// Only the real unexpected shutdown., Normal Close Code (1000, 1001, 1005)Do Not Record
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseNormalClosure,      // 1000 - Normal Close
				websocket.CloseGoingAway,          // 1001 - Client Leaves
				websocket.CloseNoStatusReceived) { // 1005 - No state close
				logger.Error("WebSocket unexpected close for task %s: %v", taskID, err)
			}
			// Normal closes unrecorded logs, Keep quiet.
			return
		}

		// Process client messages
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err == nil {
			if msgType, ok := msg["type"].(string); ok {
				switch msgType {
				case "ping":
					// log.Printf("Received ping from task: %s", taskID) // Reducing noise
				case "pong":
					// Client Responsepong
					conn.SetReadDeadline(time.Now().Add(pongWait))
				}
			}
		}
	}
}

// writePump Process sending heart beats to client
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

// RegisterProgressChannel Progress Channel for Register Tasks
func (h *WebSocketHandler) RegisterProgressChannel(taskID string, ch chan *scanner.ScanProgress) {
	h.chansMutex.Lock()
	h.progressChans[taskID] = ch
	h.chansMutex.Unlock()
	// log.Printf("Progress channel registered for task: %s", taskID) // Decrease Log
}

// UnregisterProgressChannel Progress trail for write-off tasks
func (h *WebSocketHandler) UnregisterProgressChannel(taskID string) {
	h.chansMutex.Lock()
	if ch, exists := h.progressChans[taskID]; exists {
		close(ch)
		delete(h.progressChans, taskID)
	}
	h.chansMutex.Unlock()
	// log.Printf("Progress channel unregistered for task: %s", taskID) // Decrease Log
}

// progressDispatcher Progress Distribution - Read and broadcast from the progress channel toWebSocketClient
func (h *WebSocketHandler) progressDispatcher() {
	ticker := time.NewTicker(100 * time.Millisecond) // Every100msCheck it out.
	defer ticker.Stop()

	for range ticker.C {
		h.chansMutex.RLock()
		for taskID, progressChan := range h.progressChans {
			// Non-strict reading progress
			select {
			case progress, ok := <-progressChan:
				if !ok {
					// Passage closed.
					continue
				}
				// Broadcast to all subscribers of the task
				h.broadcastProgress(taskID, progress)
			default:
				// No new progress, Skip
			}
		}
		h.chansMutex.RUnlock()
	}
}

// broadcastProgress Broadcast progress to all clients of the given task
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

// BroadcastProgress Radio Simple Progress Update (Achieved scanner.ProgressHandler Interface)
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

// BroadcastTaskComplete Radio mission complete.
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

// GetProgressChannel Get or create a progress channel for tasks
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
