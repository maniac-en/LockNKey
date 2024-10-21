package logutil

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

// InitLogger initializes the logger based on configuration.
func InitLogger(logFileName string) error {
	execDir, err := getExecutableDir()
	if err != nil {
		return fmt.Errorf("failed to determine executable directory: %v", err)
	}

	// Ensure the log file and its directories exist
	if err := ensureLogFile(filepath.Join(execDir, logFileName)); err != nil {
		return fmt.Errorf("could not create log file: %v", err)
	}

	// Open log file for writing
	logFile, err := os.OpenFile(filepath.Join(execDir, logFileName), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("could not open log file: %v", err)
	}

	// Set handler options with the debug level
	logOptions := &slog.HandlerOptions{
		Level: slog.LevelDebug, // Set to debug level to include all log levels
	}

	// Create a new logger with JSON handler and the specified options
	logger = slog.New(slog.NewJSONHandler(logFile, logOptions))

	return nil
}

// GetLogger returns the initialized logger instance
func GetLogger() *slog.Logger {
	if logger == nil {
		fmt.Println("Logger not initialized. Call InitLogger first.")
		os.Exit(1) // Exit the program if the logger isn't initialized
	}
	return logger
}

// getExecutableDir returns the directory where the executable is located
func getExecutableDir() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	execDir := filepath.Dir(execPath)
	return execDir, nil
}

// ensureLogFile ensures that the log file and its parent directories exist
func ensureLogFile(logFilePath string) error {
	// Create parent directories if they don't exist
	if err := os.MkdirAll(filepath.Dir(logFilePath), 0755); err != nil {
		return fmt.Errorf("failed to create log file directories: %v", err)
	}

	// Create the log file if it doesn't exist
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		file, err := os.Create(logFilePath)
		if err != nil {
			return fmt.Errorf("failed to create log file: %v", err)
		}
		defer file.Close()
		fmt.Println("Log file created successfully at", logFilePath)
	}

	return nil
}
