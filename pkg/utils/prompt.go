package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// UnsecurePrompt shows the user input while reading it
func UnsecurePrompt(prompt string) (string, error) {
	fmt.Print(prompt) // Display the prompt
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	trimmedInput := strings.TrimSpace(input)
	return trimmedInput, nil
}

// SecurePrompt hides user input while reading it
func SecurePrompt(prompt string) (string, error) {
	// Check if the terminal is attached to stdin (respecting IPC mechanism)
	if !term.IsTerminal(int(syscall.Stdin)) {
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(input), nil
	}

	fmt.Print(prompt)
	byteInput, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	input := strings.TrimSpace(string(byteInput))
	fmt.Println() // Print a newline after user input for better formatting

	return input, nil
}
