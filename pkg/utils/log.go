package utils

import (
	"fmt"
	"golang.org/x/exp/slog"
	"os"
	"path/filepath"
)

type LogConfig struct {
	Level    string `yaml:"level"`
	FilePath string `yaml:"file_path"`
}

var logger *slog.Logger

// InitLogger sets up the logger with the specified log file name
func InitLogger(logFileName string) error {
	execDir, err := getExecutableDir()
	if err != nil {
		return fmt.Errorf("failed to determine executable directory: %w", err)
	}

	logFilePath := filepath.Join(execDir, logFileName)

	// Ensure the log file and its directories exist
	if err := ensureLogFile(logFilePath); err != nil {
		return fmt.Errorf("could not create log file: %w", err)
	}

	// Open the log file for writing
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open log file: %w", err)
	}

	// Set handler options with the debug level to capture all logs
	logOptions := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}

	// Create a logger with a JSON handler for structured logging
	logger = slog.New(slog.NewJSONHandler(logFile, logOptions))

	return nil
}

// GetLogger returns the logger instance if initialized, otherwise exits the
// program
func GetLogger() *slog.Logger {
	if logger == nil {
		fmt.Println("Logger is not initialized. Please call InitLogger first.")
		os.Exit(1) // Exit if the logger is not initialized
	}
	return logger
}

// getExecutableDir returns the directory where the executable is located
func getExecutableDir() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(execPath), nil
}

// ensureLogFile makes sure the log file and its parent directories exist
func ensureLogFile(logFilePath string) error {
	// Create parent directories if they don't already exist
	if err := os.MkdirAll(filepath.Dir(logFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create directories for log file: %w", err)
	}

	// Create the log file if it doesn't exist
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		file, err := os.Create(logFilePath)
		if err != nil {
			return fmt.Errorf("failed to create log file: %w", err)
		}
		defer file.Close()
		fmt.Println("Log file created at", logFilePath)
	}

	return nil
}
