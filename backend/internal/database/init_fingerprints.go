package database

import (
"log"

"github.com/reconmaster/backend/internal/models"
)

// InitDefaultFingerprints Initialize default fingerprint library
// Attention.: This function has been abandoned, Use now services.FingerprintLoader.LoadDefaultFingerprints()
// From finger.yaml File Loading Fingerprint Data
func InitDefaultFingerprints() error {
	// Check if there's any fingerprints.
	var count int64
	DB.Model(&models.Fingerprint{}).Count(&count)
	if count > 0 {
		log.Println("Fingerprint library already initialized")
		return nil
	}

	log.Println("Fingerprint library is empty. Please use FingerprintLoader to load from finger.yaml")
	return nil
}
