package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"github.com/reconmaster/backend/internal/proxypool"
)

type ProxyHandler struct{}

func NewProxyHandler() *ProxyHandler { return &ProxyHandler{} }

type proxyBatchInput struct {
	IDs []string `json:"ids" binding:"required"`
}

func normalizeProxyIDs(ids []string) ([]string, error) {
	if len(ids) == 0 || len(ids) > 1000 {
		return nil, fmt.Errorf("batch size must be between 1 and 1000")
	}
	seen := make(map[string]struct{}, len(ids))
	values := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			return nil, fmt.Errorf("proxy id cannot be empty")
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		values = append(values, id)
	}
	return values, nil
}

type proxyInput struct {
	Name      string `json:"name" binding:"required"`
	Scheme    string `json:"scheme" binding:"required"`
	Host      string `json:"host" binding:"required"`
	Port      int    `json:"port" binding:"required"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	IsEnabled *bool  `json:"is_enabled"`
}

func validateProxyInput(input proxyInput) error {
	return (models.ProxyEndpoint{
		Name: input.Name, Scheme: input.Scheme, Host: input.Host, Port: input.Port,
		Username: input.Username, Password: input.Password,
	}).Validate()
}

func applyProxyInput(value *models.ProxyEndpoint, input proxyInput, preservePassword bool) {
	value.Name = strings.TrimSpace(input.Name)
	value.Scheme = strings.ToLower(strings.TrimSpace(input.Scheme))
	value.Host = strings.TrimSpace(input.Host)
	value.Port = input.Port
	value.Username = input.Username
	if input.Password != "" || !preservePassword {
		value.Password = input.Password
	}
	if input.Username == "" {
		value.Password = ""
	}
	if input.IsEnabled != nil {
		value.IsEnabled = *input.IsEnabled
	}
}

func (h *ProxyHandler) List(c *gin.Context) {
	var values []models.ProxyEndpoint
	if err := database.DB.Order("created_at DESC").Find(&values).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list proxies"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"proxies": values})
}

func (h *ProxyHandler) Create(c *gin.Context) {
	var input proxyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := validateProxyInput(input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	enabled := true
	value := models.ProxyEndpoint{IsEnabled: enabled, Status: "unknown"}
	applyProxyInput(&value, input, false)
	if err := database.DB.Create(&value).Error; err != nil {
		c.JSON(409, gin.H{"error": "proxy address already exists"})
		return
	}
	proxypool.Refresh()
	c.JSON(http.StatusCreated, value)
}

func (h *ProxyHandler) BatchCreate(c *gin.Context) {
	var input struct {
		Proxies []proxyInput `json:"proxies" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if len(input.Proxies) == 0 || len(input.Proxies) > 1000 {
		c.JSON(400, gin.H{"error": "batch size must be between 1 and 1000"})
		return
	}
	created, skipped := 0, 0
	errors := make([]gin.H, 0)
	for index, item := range input.Proxies {
		if err := validateProxyInput(item); err != nil {
			skipped++
			errors = append(errors, gin.H{"index": index + 1, "name": item.Name, "error": err.Error()})
			continue
		}
		value := models.ProxyEndpoint{IsEnabled: true, Status: "unknown"}
		applyProxyInput(&value, item, false)
		if database.DB.Create(&value).Error != nil {
			skipped++
			errors = append(errors, gin.H{"index": index + 1, "name": item.Name, "error": "duplicate proxy address"})
		} else {
			created++
		}
	}
	proxypool.Refresh()
	c.JSON(http.StatusOK, gin.H{"created": created, "skipped": skipped, "errors": errors, "example": "socks5://username:password@127.0.0.1:1080"})
}

func (h *ProxyHandler) BatchDelete(c *gin.Context) {
	var input proxyBatchInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ids, err := normalizeProxyIDs(input.IDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result := database.DB.Where("id IN ?", ids).Delete(&models.ProxyEndpoint{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete proxies"})
		return
	}
	proxypool.Refresh()
	c.JSON(http.StatusOK, gin.H{"requested": len(ids), "deleted": result.RowsAffected})
}

func (h *ProxyHandler) BatchTest(c *gin.Context) {
	var input proxyBatchInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ids, err := normalizeProxyIDs(input.IDs)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var values []models.ProxyEndpoint
	if err := database.DB.Where("id IN ?", ids).Find(&values).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load proxies"})
		return
	}

	var wg sync.WaitGroup
	jobs := make(chan *models.ProxyEndpoint)
	workers := 10
	if len(values) < workers {
		workers = len(values)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for value := range jobs {
				proxypool.CheckOne(value)
			}
		}()
	}
	for i := range values {
		jobs <- &values[i]
	}
	close(jobs)
	wg.Wait()
	for i := range values {
		if err := database.DB.Save(&values[i]).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save proxy test results"})
			return
		}
	}
	proxypool.Refresh()

	healthy := 0
	for _, value := range values {
		if value.Status == "healthy" {
			healthy++
		}
	}
	c.JSON(http.StatusOK, gin.H{"requested": len(ids), "tested": len(values), "healthy": healthy, "dead": len(values) - healthy})
}

func (h *ProxyHandler) Update(c *gin.Context) {
	var value models.ProxyEndpoint
	if database.DB.First(&value, "id = ?", c.Param("id")).Error != nil {
		c.JSON(404, gin.H{"error": "proxy not found"})
		return
	}
	var input proxyInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := validateProxyInput(input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	addressChanged := value.Scheme != input.Scheme || value.Host != input.Host || value.Port != input.Port || value.Username != input.Username || input.Password != ""
	applyProxyInput(&value, input, true)
	if addressChanged {
		value.Status = "unknown"
		value.LastError = ""
	}
	if err := database.DB.Save(&value).Error; err != nil {
		c.JSON(409, gin.H{"error": "proxy address already exists"})
		return
	}
	proxypool.Refresh()
	c.JSON(http.StatusOK, value)
}

func (h *ProxyHandler) Delete(c *gin.Context) {
	result := database.DB.Delete(&models.ProxyEndpoint{}, "id = ?", c.Param("id"))
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete proxy"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy not found"})
		return
	}
	proxypool.Refresh()
	c.JSON(http.StatusOK, gin.H{"message": "proxy deleted"})
}

func (h *ProxyHandler) Test(c *gin.Context) {
	var value models.ProxyEndpoint
	if database.DB.First(&value, "id = ?", c.Param("id")).Error != nil {
		c.JSON(404, gin.H{"error": "proxy not found"})
		return
	}
	err := proxypool.CheckOne(&value)
	if saveErr := database.DB.Save(&value).Error; saveErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save proxy test result"})
		return
	}
	proxypool.Refresh()
	if err != nil {
		c.JSON(http.StatusBadGateway, value)
		return
	}
	c.JSON(http.StatusOK, value)
}

func (h *ProxyHandler) TestAll(c *gin.Context) {
	tested, healthy, dead, err := proxypool.CheckAll()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to test proxy pool"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"tested": tested, "healthy": healthy, "dead": dead})
}

func ParseProxyURL(raw string, index int) (proxyInput, error) {
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return proxyInput{}, err
	}
	port := 0
	fmt.Sscanf(value.Port(), "%d", &port)
	input := proxyInput{Name: fmt.Sprintf("proxy-%03d", index+1), Scheme: value.Scheme, Host: value.Hostname(), Port: port}
	if value.User != nil {
		input.Username = value.User.Username()
		input.Password, _ = value.User.Password()
	}
	return input, validateProxyInput(input)
}
