package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User User Model
type User struct {
	ID                 string         `gorm:"type:varchar(36);primaryKey" json:"id"`
	Username           string         `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Password           string         `gorm:"type:varchar(255);not null" json:"-"` // No, I'm not.JSONBack in
	Email              string         `gorm:"type:varchar(100);uniqueIndex" json:"email"`
	Nickname           string         `gorm:"type:varchar(100)" json:"nickname"`
	Avatar             string         `gorm:"type:varchar(255)" json:"avatar"`
	Role               string         `gorm:"type:varchar(20);default:'user'" json:"role"`     // admin, user
	Status             string         `gorm:"type:varchar(20);default:'active'" json:"status"` // active, disabled
	MustChangePassword bool           `gorm:"default:false" json:"must_change_password"`       // Whether passwords must be changed (First Login)
	LastLogin          *time.Time     `json:"last_login"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName Specifying a tab name
func (User) TableName() string {
	return "users"
}

// BeforeCreate Create a pre-hand hook
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

// generateID GenerateID (Auxiliary Functions)
func generateID(prefix string) string {
	return fmt.Sprintf("%s_%s", prefix, uuid.New().String())
}

// SetPassword Set Password (Encryption)
func (u *User) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

// CheckPassword Authentication password
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

// IsAdmin Whether to be a administrator
func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// IsActive Whether to activate
func (u *User) IsActive() bool {
	return u.Status == "active"
}

// UserSession User Session
type UserSession struct {
	ID        string    `gorm:"type:varchar(36);primaryKey" json:"id"`
	UserID    string    `gorm:"type:varchar(36);index;not null" json:"user_id"`
	Token     string    `gorm:"type:varchar(500);uniqueIndex;not null" json:"token"`
	IP        string    `gorm:"type:varchar(50)" json:"ip"`
	UserAgent string    `gorm:"type:varchar(500)" json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// TableName Specifying a tab name
func (UserSession) TableName() string {
	return "user_sessions"
}

// LoginRequest Login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest Registration requests
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=12,max=72"`
	Email    string `json:"email" binding:"required,email"`
	Nickname string `json:"nickname"`
}

// UpdatePasswordRequest Change password request
type UpdatePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=12,max=72"`
}

// UpdateProfileRequest Request for updated information
type UpdateProfileRequest struct {
	Nickname string `json:"nickname"`
	Email    string `json:"email" binding:"omitempty,email"`
	Avatar   string `json:"avatar"`
}
