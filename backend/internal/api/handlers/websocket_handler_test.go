package handlers

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/reconmaster/backend/internal/scanner"
)

func TestWebSocketSerializesConcurrentBroadcasts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &WebSocketHandler{
		clients:       make(map[*websocket.Conn]*webSocketClient),
		progressChans: make(map[string]chan *scanner.ScanProgress),
	}
	router := gin.New()
	router.GET("/ws", handler.HandleWebSocket)
	server := httptest.NewServer(router)
	defer server.Close()

	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?task_id=task-1"
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, _, err := client.ReadMessage(); err != nil {
		t.Fatalf("read welcome message: %v", err)
	}

	const writers = 8
	const messagesPerWriter = 20
	readDone := make(chan error, 1)
	go func() {
		for index := 0; index < writers*messagesPerWriter; index++ {
			if _, _, err := client.ReadMessage(); err != nil {
				readDone <- err
				return
			}
		}
		readDone <- nil
	}()

	var wait sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		writer := writer
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < messagesPerWriter; index++ {
				if writer%2 == 0 {
					handler.BroadcastProgress("task-1", index, fmt.Sprintf("writer-%d", writer))
				} else {
					handler.BroadcastTaskComplete("task-1", "running", fmt.Sprintf("writer-%d", writer))
				}
			}
		}()
	}
	wait.Wait()
	if err := <-readDone; err != nil {
		t.Fatalf("read concurrent broadcast: %v", err)
	}
}
