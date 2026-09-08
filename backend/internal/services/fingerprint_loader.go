package services

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"gopkg.in/yaml.v3"
)

// FingerprintLoader Fingerprint loader
type FingerprintLoader struct{}

// NewFingerprintLoader Create Fingerprint Loader
func NewFingerprintLoader() *FingerprintLoader {
	return &FingerprintLoader{}
}

// LoadDefaultFingerprints Load default fingerprint library (On first start)
func (l *FingerprintLoader) LoadDefaultFingerprints() error {
	// Check if there's any fingerprints.
	var count int64
	database.DB.Model(&models.Fingerprint{}).Count(&count)
	
	if count > 0 {
		fmt.Printf("Existing in database %d A fingerprint., Skip Autoload\n", count)
		return nil
	}

	fmt.Println("First start, Start loading default fingerprint library...")

	// Path to fingerprint files
	fingerprintFile := "configs/fingerprints/finger.yaml"
	
	// Check if the file exists
	if _, err := os.Stat(fingerprintFile); os.IsNotExist(err) {
		fmt.Printf("Warning: Default fingerprint file does not exist: %s\n", fingerprintFile)
		return nil
	}

	// Read File
	file, err := os.Open(fingerprintFile)
	if err != nil {
		return fmt.Errorf("failed to open fingerprint file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read fingerprint file: %v", err)
	}

	// Parsing YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	fmt.Printf("Successfully parsed YAML, Total %d A fingerprint definition.\n", len(rawData))

	// Convert and import fingerprints
	imported, skipped, failed := l.importFingerprints(rawData)

	fmt.Printf("Fingerprint loaded complete.！Success: %d, Skip: %d, Failed: %d\n", imported, skipped, failed)
	
	return nil
}

// importFingerprints Importing fingerprint data
func (l *FingerprintLoader) importFingerprints(rawData map[string]interface{}) (imported, skipped, failed int) {
	totalFingerprints := len(rawData)
	processedCount := 0
	
	for name, value := range rawData {
		processedCount++
		if processedCount%1000 == 0 {
			fmt.Printf("Process progress: %d/%d (Success:%d, Skip:%d, Failed:%d)\n",
				processedCount, totalFingerprints, imported, skipped, failed)
		}
		
		// Skip Empty Name
		if name == "" {
			failed++
			continue
		}

		// Parse the fingerprint object, including its DSL fields.
		fpData, ok := value.(map[string]interface{})
		if !ok {
			failed++
			continue
		}

		// Fetch dsl Rule array
		dslInterface, ok := fpData["dsl"]
		if !ok {
			failed++
			continue
		}

		dslArray, ok := dslInterface.([]interface{})
		if !ok {
			failed++
			continue
		}

		// Convert to String Array
		var dslRules []string
		for _, item := range dslArray {
			if str, ok := item.(string); ok {
				dslRules = append(dslRules, str)
			}
		}

		if len(dslRules) == 0 {
			failed++
			continue
		}

		// Check if it exists (Weight by name)
		var existing models.Fingerprint
		err := database.DB.Where("name = ?", name).
			First(&existing).Error

		if err == nil {
			// Existing, Skip
			skipped++
			continue
		}

		// Create fingerprint log
		fingerprint := &models.Fingerprint{
			Name:        name,
			Category:    "Web", // Default Category
			DSL:         dslRules,
			Description: fmt.Sprintf("Import from default fingerprint library: %s", name),
			IsEnabled:   true,
		}

		// Insert Database
		if err := database.DB.Create(fingerprint).Error; err != nil {
			// Ignore duplicate key error
			if !strings.Contains(err.Error(), "duplicate") && 
			   !strings.Contains(err.Error(), "unique constraint") {
				if failed < 100 {
					fmt.Printf("Failed to insert fingerprint: %s - %v\n", name, err)
				}
			}
			failed++
			continue
		}

		imported++
	}

	return
}

// LoadFingerprintsFromFile Load fingerprints from files (ForAPIUse)
func (l *FingerprintLoader) LoadFingerprintsFromFile(filePath string) (imported, skipped, failed int, err error) {
	// Check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	
	if ext != ".yaml" && ext != ".yml" {
		return 0, 0, 0, fmt.Errorf("unsupported file format: %s", ext)
	}

	// Read File
	file, err := os.Open(filePath)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("failed to read file: %v", err)
	}

	// Parsing YAML
	var rawData map[string]interface{}
	if err := yaml.Unmarshal(data, &rawData); err != nil {
		return 0, 0, 0, fmt.Errorf("failed to parse YAML: %v", err)
	}

	// Import Fingerprints
	imported, skipped, failed = l.importFingerprints(rawData)
	
	return imported, skipped, failed, nil
}
