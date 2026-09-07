package handlers

import (
	"net/http"
	"sort"

	"github.com/gin-gonic/gin"
	"github.com/reconmaster/backend/internal/searchquery"
	"gorm.io/gorm"
)

func applyAdvancedSearch(c *gin.Context, query *gorm.DB, fields map[string]string, defaults []string) (*gorm.DB, bool) {
	next, err := searchquery.Apply(query, c.Query("q"), fields, defaults)
	if err == nil {
		return next, true
	}
	fieldNames := make([]string, 0, len(fields))
	for name := range fields {
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)
	c.JSON(http.StatusBadRequest, gin.H{
		"error":            "检索语法错误：" + err.Error(),
		"example":          `nginx && !test || title:"管理系统"`,
		"supported_fields": fieldNames,
	})
	return query, false
}
