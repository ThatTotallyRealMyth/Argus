package logger

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Logger Log Log Recorder
type Logger struct {
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	logFile     *os.File
}

var GlobalLogger *Logger

// InitLogger Initialization log
func InitLogger(logPath string, level string) error {
	// Create Log Directory
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open Log File
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	GlobalLogger = &Logger{
		infoLogger:  log.New(logFile, "[INFO] ", log.LstdFlags),
		errorLogger: log.New(logFile, "[ERROR] ", log.LstdFlags),
		debugLogger: log.New(logFile, "[DEBUG] ", log.LstdFlags),
		logFile:     logFile,
	}

	// Output simultaneously to Console
	if level == "debug" {
		GlobalLogger.infoLogger.SetOutput(os.Stdout)
		GlobalLogger.errorLogger.SetOutput(os.Stderr)
		GlobalLogger.debugLogger.SetOutput(os.Stdout)
	}

	return nil
}

// Info RecordsinfoLog
func (l *Logger) Info(format string, v ...interface{}) {
	l.infoLogger.Printf(format, v...)
}

// Error RecordserrorLog
func (l *Logger) Error(format string, v ...interface{}) {
	l.errorLogger.Printf(format, v...)
}

// Debug RecordsdebugLog
func (l *Logger) Debug(format string, v ...interface{}) {
	l.debugLogger.Printf(format, v...)
}

// Close Close Log File
func (l *Logger) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// RotateLog Log rotation
func (l *Logger) RotateLog(logPath string) error {
	// Simple log rotation
	if l.logFile != nil {
		l.logFile.Close()
	}

	// Rename Old File
	timestamp := time.Now().Format("20060102_150405")
	oldPath := logPath + "." + timestamp
	os.Rename(logPath, oldPath)

	// Create New File
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}

	l.logFile = logFile
	l.infoLogger.SetOutput(logFile)
	l.errorLogger.SetOutput(logFile)
	l.debugLogger.SetOutput(logFile)

	return nil
}

// Easy function
func Info(format string, v ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.Info(format, v...)
	} else {
		log.Printf("[INFO] "+format, v...)
	}
}

func Error(format string, v ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.Error(format, v...)
	} else {
		log.Printf("[ERROR] "+format, v...)
	}
}

func Debug(format string, v ...interface{}) {
	if GlobalLogger != nil {
		GlobalLogger.Debug(format, v...)
	} else {
		log.Printf("[DEBUG] "+format, v...)
	}
}
