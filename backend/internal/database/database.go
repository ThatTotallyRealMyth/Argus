package database

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Config Database Configuration
type Config struct {
	Host         string
	Port         int
	User         string
	Password     string
	DBName       string
	SSLMode      string
	MaxIdleConns int
	MaxOpenConns int
}

// Initialize Initialize database connections
func Initialize(config Config) error {
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == 0 {
		config.Port = 5432
	}
	if config.User == "" {
		config.User = "admin"
	}
	if config.DBName == "" {
		config.DBName = "arl_vp3"
	}
	if config.SSLMode == "" {
		config.SSLMode = "disable"
	}
	userInfo := url.User(config.User)
	if config.Password != "" {
		userInfo = url.UserPassword(config.User, config.Password)
	}
	dsnURL := url.URL{
		Scheme: "postgres",
		User:   userInfo,
		Host:   net.JoinHostPort(config.Host, strconv.Itoa(config.Port)),
		Path:   "/" + config.DBName,
	}
	query := dsnURL.Query()
	query.Set("sslmode", config.SSLMode)
	dsnURL.RawQuery = query.Encode()
	dsn := dsnURL.String()

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Error),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get database instance: %w", err)
	}

	// Set connection pool
	sqlDB.SetMaxIdleConns(config.MaxIdleConns)
	sqlDB.SetMaxOpenConns(config.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// AutoMove
	if err := autoMigrate(); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Initializes the old hard-coded fingerprint., For Use YAML Load File
	// if err := InitDefaultFingerprints(); err != nil {
	// 	log.Printf("Warning: Failed to initialize fingerprints: %v", err)
	// }

	// Initialization of built-in sensitive information rules
	if err := InitBuiltInSensitiveRules(DB); err != nil {
		log.Printf("Warning: Failed to initialize built-in sensitive rules: %v", err)
	}

	log.Println("Database connected successfully")
	return nil
}

// autoMigrate AutoMove Database Table
func autoMigrate() error {
	// Data cleansing before the migration is performed
	if err := migrateOldFingerprints(); err != nil {
		log.Printf("Warning: Failed to migrate old fingerprints: %v", err)
	}

	return DB.AutoMigrate(
		&models.User{},
		&models.UserSession{},
		&models.Task{},
		&models.TaskLog{},
		&models.AssetEntity{},
		&models.AssetObservation{},
		&models.CanonicalAssetRelation{},
		&models.AssetRelationObservation{},
		&models.AssetVulnerabilityLink{},
		&models.AssetChange{},
		&models.AssetLeadTriage{},
		&models.ScanScope{},
		&models.EnterpriseQuery{},
		&models.EnterpriseAsset{},
		&models.Domain{},
		&models.IP{},
		&models.Port{},
		&models.Site{},
		&models.URL{},
		&models.CrawlerResult{},
		&models.HTTPTransaction{},
		&models.Vulnerability{},
		&models.Monitor{},
		&models.Policy{},
		&models.MonitorResult{},
		&models.AssetGroup{},
		&models.AssetGroupItem{},
		&models.Setting{},
		&models.ProxyEndpoint{},
		&models.Dictionary{},
		&models.Fingerprint{},
		&models.PoC{},
		&models.PoCExecutionLog{},
		&models.GitHubMonitor{},
		&models.GitHubMonitorResult{},
		&models.ScheduledTask{},
		&models.ScheduledTaskLog{},
		&models.AssetTag{},
		&models.AssetTagRelation{},
		&models.SensitiveRule{},
		&models.SensitiveMatch{},
	)
}

// InitDictionaries Initialize Dictionary Data
func InitDictionaries() error {
	// Scan Dictionary Directory
	dictTypes := []string{"domain", "port", "file"}

	for _, dictType := range dictTypes {
		dictDir := fmt.Sprintf("./configs/dicts/%s", dictType)

		// Check if directory exists
		if _, err := os.Stat(dictDir); os.IsNotExist(err) {
			continue
		}

		// Read files in directory
		files, err := os.ReadDir(dictDir)
		if err != nil {
			log.Printf("Failed to read dict directory %s: %v", dictDir, err)
			continue
		}

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".txt") {
				continue
			}

			filePath := fmt.Sprintf("%s/%s", dictDir, file.Name())

			// Check whether the database exists
			var existingDict models.Dictionary
			if err := DB.Where("file_path = ?", filePath).First(&existingDict).Error; err == nil {
				// Existing, Skip
				continue
			}

			// Fetching file information
			fileInfo, err := os.Stat(filePath)
			if err != nil {
				continue
			}

			// Number of statistical lines
			lineCount := countFileLines(filePath)

			// Generate dictionary names (Remove the time stamp prefix and.txtSuffix)
			name := strings.TrimSuffix(file.Name(), ".txt")
			// If file name is stamped with time_Start, Take the time stamp off.
			if idx := strings.Index(name, "_"); idx > 0 && idx < 15 {
				name = name[idx+1:]
			}

			// Create Dictionary Records
			dict := models.Dictionary{
				Name:        name,
				Type:        dictType,
				FilePath:    filePath,
				Size:        fileInfo.Size(),
				LineCount:   lineCount,
				Description: fmt.Sprintf("System settings%sDictionary", dictType),
				IsDefault:   file.Name() == "big.txt", // big.txt Set as Default
				CreatedBy:   "system",
			}

			if err := DB.Create(&dict).Error; err != nil {
				log.Printf("Failed to create dictionary record for %s: %v", filePath, err)
			} else {
				log.Printf("Initialized dictionary: %s (%d lines)", name, lineCount)
			}
		}
	}

	return nil
}

// countFileLines Number of statistical documents
func countFileLines(filePath string) int {
	file, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lineCount++
		}
	}

	return lineCount
}

// migrateOldFingerprints Move old fingerprint data
func migrateOldFingerprints() error {
	// Check whether the form exists
	if !DB.Migrator().HasTable(&models.Fingerprint{}) {
		log.Println("Fingerprints table does not exist yet, skipping migration")
		return nil
	}

	// Check for old fields rule_type and rule_content
	hasOldFields := DB.Migrator().HasColumn(&models.Fingerprint{}, "rule_type") ||
		DB.Migrator().HasColumn(&models.Fingerprint{}, "rule_content")

	if !hasOldFields {
		log.Println("Old fingerprint fields not found, skipping migration")
		return nil
	}

	log.Println("Detected old fingerprint schema, performing migration...")

	// Remove all old fingerprints (Because the format is not compatible.)
	result := DB.Exec("DELETE FROM fingerprints")
	if result.Error != nil {
		return fmt.Errorf("failed to delete old fingerprints: %v", result.Error)
	}

	log.Printf("Deleted %d old fingerprint records", result.RowsAffected)

	// Remove Old Fields
	oldColumns := []string{"rule_type", "rule_content", "confidence"}
	for _, col := range oldColumns {
		if DB.Migrator().HasColumn(&models.Fingerprint{}, col) {
			if err := DB.Migrator().DropColumn(&models.Fingerprint{}, col); err != nil {
				log.Printf("Warning: failed to drop %s column: %v", col, err)
			} else {
				log.Printf("Dropped old column: %s", col)
			}
		}
	}

	log.Println("Old fingerprint schema migration completed")
	return nil
}

// Close Close Database Connection
func Close() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
