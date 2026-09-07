package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/reconmaster/backend/internal/config"
	"github.com/reconmaster/backend/internal/database"
	"github.com/reconmaster/backend/internal/models"
	"golang.org/x/term"
)

func main() {
	usernameFlag := flag.String("username", envOrDefault("ADMIN_USERNAME", "admin"), "initial administrator username")
	emailFlag := flag.String("email", envOrDefault("ADMIN_EMAIL", "admin@localhost"), "initial administrator email")
	resetUsername := flag.String("reset-password", "", "reset the named user's password using a hidden prompt")
	flag.Parse()

	if err := config.LoadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	if err := database.Initialize(database.Config{
		Host: config.GlobalConfig.Database.Host, Port: config.GlobalConfig.Database.Port,
		User: config.GlobalConfig.Database.User, Password: config.GlobalConfig.Database.Password,
		DBName: config.GlobalConfig.Database.DBName, SSLMode: config.GlobalConfig.Database.SSLMode,
		MaxIdleConns: config.GlobalConfig.Database.MaxIdleConns, MaxOpenConns: config.GlobalConfig.Database.MaxOpenConns,
	}); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()

	if strings.TrimSpace(*resetUsername) != "" {
		resetPassword(strings.TrimSpace(*resetUsername))
		return
	}

	var count int64
	if err := database.DB.Model(&models.User{}).Where("role = ?", "admin").Count(&count).Error; err != nil {
		log.Fatalf("Failed to check administrators: %v", err)
	}
	if count > 0 {
		log.Println("Admin user already exists")
		return
	}

	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		password = promptPassword("Create administrator password: ")
	}
	if err := validatePassword(password); err != nil {
		log.Fatal(err)
	}

	admin := models.User{
		ID: uuid.New().String(), Username: strings.TrimSpace(*usernameFlag),
		Email: strings.TrimSpace(*emailFlag), Nickname: "系统管理员",
		Role: "admin", Status: "active", MustChangePassword: false,
	}
	if admin.Username == "" || admin.Email == "" {
		log.Fatal("administrator username and email are required")
	}
	if err := admin.SetPassword(password); err != nil {
		log.Fatalf("Failed to hash administrator password: %v", err)
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		log.Fatalf("Failed to create administrator: %v", err)
	}

	fmt.Printf("Administrator %q created successfully.\n", admin.Username)
}

func resetPassword(username string) {
	var user models.User
	if err := database.DB.First(&user, "username = ?", username).Error; err != nil {
		log.Fatalf("User %q not found", username)
	}
	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		password = promptPassword("New password: ")
	}
	if err := validatePassword(password); err != nil {
		log.Fatal(err)
	}
	if err := user.SetPassword(password); err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	user.MustChangePassword = false
	tx := database.DB.Begin()
	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		log.Fatalf("Failed to update password: %v", err)
	}
	if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserSession{}).Error; err != nil {
		tx.Rollback()
		log.Fatalf("Failed to revoke sessions: %v", err)
	}
	if err := tx.Commit().Error; err != nil {
		log.Fatalf("Failed to commit password reset: %v", err)
	}
	fmt.Printf("Password for %q was reset and all sessions were revoked.\n", username)
}

func promptPassword(prompt string) string {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Fatal("interactive terminal required; set ADMIN_PASSWORD for non-interactive initialization")
	}
	fmt.Print(prompt)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	fmt.Print("Confirm password: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		log.Fatalf("Failed to read password confirmation: %v", err)
	}
	if string(first) != string(second) {
		log.Fatal("passwords do not match")
	}
	return string(first)
}

func validatePassword(password string) error {
	if len(password) < 12 {
		return fmt.Errorf("password must contain at least 12 characters")
	}
	if len(password) > 72 {
		return fmt.Errorf("password must not exceed 72 bytes")
	}
	lower := strings.ToLower(strings.TrimSpace(password))
	if strings.Contains(lower, "replace-with") || strings.Contains(lower, "change-me") || strings.Contains(lower, "changeme") {
		return fmt.Errorf("password must not be an example placeholder")
	}
	return nil
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
