package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/reconmaster/backend/internal/config"
)

var (
	// JWTSecret JWTKey, Read From Profile
	JWTSecret []byte

	// TokenExpiration tokenExpiration
	TokenExpiration = 24 * time.Hour

	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// Init InitializationJWTConfigure
// JWTKeys must be visible, Default value not allowed
func Init() {
	if config.GlobalConfig == nil || config.GlobalConfig.JWT.Secret == "" {
		panic("JWT secret is not configured. Set jwt.secret in config.yaml or JWT_SECRET env var. " +
			"Refusing to start with an empty/insecure secret.")
	}
	JWTSecret = []byte(config.GlobalConfig.JWT.Secret)
}

// Claims JWTStatement
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken GenerateJWT token
func GenerateToken(userID, username, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(TokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "ARL_Vp3",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JWTSecret)
}

// ParseToken ParsingJWT token
// Even if token Expiration, And he'll return. claims ♪ To RefreshToken Use
func ParseToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("ARL_Vp3"))

	// Try to extract claims (Even if token Invalid or expired, claims It may still be available.)
	if token != nil {
		if claims, ok := token.Claims.(*Claims); ok {
			if err == nil {
				return claims, nil
			}
			if errors.Is(err, jwt.ErrTokenExpired) {
				return claims, ErrExpiredToken
			}
		}
	}

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	return nil, ErrInvalidToken
}

// RefreshToken Refreshtoken
func RefreshToken(tokenString string) (string, error) {
	claims, err := ParseToken(tokenString)
	if err != nil && !errors.Is(err, ErrExpiredToken) {
		return "", err
	}

	// Generate newtoken
	return GenerateToken(claims.UserID, claims.Username, claims.Role)
}

// HashToken returns the irreversible identifier stored in the session table.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
