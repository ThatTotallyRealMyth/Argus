package cache

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

var Client *redis.Client
var ctx = context.Background()

// Config RedisConfigure
type Config struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// Initialize InitializationRedisConnection
func Initialize(config Config) error {
	Client = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", config.Host, config.Port),
		Password: config.Password,
		DB:       config.DB,
	})

	// Test Connection
	_, err := Client.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}

	log.Println("Redis connected successfully")
	return nil
}

// Set Set Key Right
func Set(key string, value interface{}, expiration time.Duration) error {
	return Client.Set(ctx, key, value, expiration).Err()
}

// Get Get Key
func Get(key string) (string, error) {
	return Client.Get(ctx, key).Result()
}

// Delete Delete Key
func Delete(key string) error {
	return Client.Del(ctx, key).Err()
}

// Exists Check if key exists
func Exists(key string) (bool, error) {
	count, err := Client.Exists(ctx, key).Result()
	return count > 0, err
}

// Close CloseRedisConnection
func Close() error {
	return Client.Close()
}
