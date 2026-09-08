package database

import (
	"log"

	"github.com/reconmaster/backend/internal/models"
	"gorm.io/gorm"
)

// InitBuiltInSensitiveRules Initialization of built-in sensitive information rules
func InitBuiltInSensitiveRules(db *gorm.DB) error {
	// Check if it's been initialized
	var count int64
	db.Model(&models.SensitiveRule{}).Where("is_built_in = ?", true).Count(&count)
	if count > 0 {
		log.Println("Built-in sensitive rules already initialized, skipping...")
		return nil
	}

	log.Println("Initializing built-in sensitive rules...")

	// Preset Rule List
	builtInRules := []models.SensitiveRule{
		// ===== API Key Class =====
		{
			Name:        "AWS Access Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(AKIA[0-9A-Z]{16})`,
			Description: "Test AWS Access Key ID",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "APIKey",
			Example:     "AKIAIOSFODNN7EXAMPLE",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "AWS Secret Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]`,
			Description: "Test AWS Secret Access Key",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "APIKey",
			Example:     "aws_secret_key: \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Ariun. AccessKey",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(LTAI[A-Za-z0-9]{12,20})`,
			Description: "Test Aliun. AccessKey ID",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "APIKey",
			Example:     "LTAI4FnKxBpXXXXXXXXX",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Xing Xingyun SecretId",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(AKI[A-Za-z0-9]{32,48})`,
			Description: "Test Tung Tsing Cloud SecretId",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "APIKey",
			Example:     "AKIDxxxxxxxxxxxxxxxxxxxxxx",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "GitHub Token",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `gh[pousr]_[A-Za-z0-9]{36}`,
			Description: "Test GitHub Personal Access Token",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "APIKey",
			Example:     "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Google API Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			Description: "Test Google API Key",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "APIKey",
			Example:     "AIzaSyDxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== Certificates and Key Classes =====
		{
			Name:        "RSA Private Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `-----BEGIN RSA PRIVATE KEY-----`,
			Description: "Test RSA Private key files",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Certificate",
			Example:     "-----BEGIN RSA PRIVATE KEY-----",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "SSH Private Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----`,
			Description: "Test SSH Private key files",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Certificate",
			Example:     "-----BEGIN OPENSSH PRIVATE KEY-----",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "PGP Private Key",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			Description: "Test PGP Private Key",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Certificate",
			Example:     "-----BEGIN PGP PRIVATE KEY BLOCK-----",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== Database connection class =====
		{
			Name:        "Database connection string",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `(mysql|postgres|mongodb|redis)://[^\s'"]*:[^\s'"]*@[^\s'"]*`,
			Description: "Test database connection string (Include password for username)",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Database",
			Example:     "mysql://user:pass@localhost:3306/db",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "JDBC Connect String",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `jdbc:[a-z]+://[^\s'"]+password=[^\s'";]+`,
			Description: "Test JDBC Database connection string",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Database",
			Example:     "jdbc:mysql://host/db?user=root&password=secret",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== JWT Token Classes =====
		{
			Name:        "JWT Token",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
			Description: "Test JWT Token",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "APIKey",
			Example:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== Personal information class =====
		{
			Name:        "ID number.",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`,
			Description: "Check China mainland ID number",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Personal",
			Example:     "110101199001011234",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Cell phone number.",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `1[3-9]\d{9}`,
			Description: "Check China mainland cell phone numbers.",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "Personal",
			Example:     "13812345678",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Chile",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			Description: "Check Mailbox Addresses",
			Severity:    models.SensitiveRuleSeverityLow,
			Category:    "Personal",
			Example:     "user@example.com",
			IsEnabled:   false, // Default Disable, Avoid misreporting
			IsBuiltIn:   true,
		},

		// ===== Password class =====
		{
			Name:        "Password (Keywords)",
			Type:        models.SensitiveRuleTypeKeyword,
			Pattern:     "password,passwd,pwd,secret,token,api_key,apikey,access_token,auth_token",
			Description: "Test key with possible password",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "Password",
			Example:     "password: 123456",
			IsEnabled:   false, // Default Disable, Avoid misreporting
			IsBuiltIn:   true,
		},

		// ===== Profile Class =====
		{
			Name:        "Docker Configure leaks",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `"auths":\s*{[^}]*"auth":\s*"[A-Za-z0-9+/=]+"`,
			Description: "Test Docker Can not open message",
			Severity:    models.SensitiveRuleSeverityHigh,
			Category:    "Profile",
			Example:     `"auths": {"registry.example.com": {"auth": "dXNlcjpwYXNzd29yZA=="}}`,
			IsEnabled:   true,
			IsBuiltIn:   true,
		},

		// ===== Cloud services =====
		{
			Name:        "Slack Webhook",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
			Description: "Test Slack Webhook URL",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "APIKey",
			Example:     "hooks.slack.com/services/TXXXXXXXX/BXXXXXXXX/XXXXXXXXXXXXXXXXXXXXXXXX",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
		{
			Name:        "Telegram Bot Token",
			Type:        models.SensitiveRuleTypeRegex,
			Pattern:     `\d{8,10}:[A-Za-z0-9_-]{35}`,
			Description: "Test Telegram Bot Token",
			Severity:    models.SensitiveRuleSeverityMedium,
			Category:    "APIKey",
			Example:     "123456789:ABCdefGHIjklMNOpqrsTUVwxyz-1234567890",
			IsEnabled:   true,
			IsBuiltIn:   true,
		},
	}

	// Batch creation rules
	for i := range builtInRules {
		if err := db.Create(&builtInRules[i]).Error; err != nil {
			log.Printf("Failed to create built-in rule '%s': %v", builtInRules[i].Name, err)
			continue
		}
	}

	log.Printf("Successfully initialized %d built-in sensitive rules", len(builtInRules))
	return nil
}
