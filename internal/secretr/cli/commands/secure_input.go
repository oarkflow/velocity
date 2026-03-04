package commands

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
)

// promptPasswordWithConfirm prompts for password with confirmation
func promptPasswordWithConfirm(prompt string) (string, error) {
	if os.Getenv("SECRETR_ALLOW_INSECURE_PASSWORD_ENV") == "true" {
		if password := os.Getenv("SECRETR_PASSWORD"); password != "" {
			if confirm := os.Getenv("SECRETR_PASSWORD_CONFIRM"); confirm != "" && confirm != password {
				return "", fmt.Errorf("passwords do not match")
			}
			return password, nil
		}
	}

	password, err := promptPassword(prompt)
	if err != nil {
		return "", err
	}

	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return "", err
	}

	if password != confirm {
		return "", fmt.Errorf("passwords do not match")
	}

	return password, nil
}

// promptSecurePassword prompts for password securely (no flag support)
func promptSecurePassword(prompt string) (string, error) {
	if os.Getenv("SECRETR_ALLOW_INSECURE_PASSWORD_ENV") == "true" {
		if password := os.Getenv("SECRETR_PASSWORD"); password != "" {
			return password, nil
		}
	}

	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	return string(password), nil
}

// parseDuration parses flexible duration formats
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 5 * time.Minute, nil // default
	}

	// Handle plain numbers as seconds
	if num, err := strconv.Atoi(s); err == nil {
		return time.Duration(num) * time.Second, nil
	}

	// Normalize common formats
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "minutes", "m")
	s = strings.ReplaceAll(s, "minute", "m")
	s = strings.ReplaceAll(s, "hours", "h")
	s = strings.ReplaceAll(s, "hour", "h")
	s = strings.ReplaceAll(s, "hrs", "h")
	s = strings.ReplaceAll(s, "hr", "h")
	s = strings.ReplaceAll(s, "seconds", "s")
	s = strings.ReplaceAll(s, "second", "s")
	s = strings.ReplaceAll(s, "secs", "s")
	s = strings.ReplaceAll(s, "sec", "s")

	// Handle formats like "10minutes" -> "10m"
	re := regexp.MustCompile(`(\d+)(m|h|s)`)
	if !re.MatchString(s) {
		// Try to add 's' suffix for plain numbers
		if num, err := strconv.Atoi(s); err == nil {
			s = fmt.Sprintf("%ds", num)
		}
	}

	return time.ParseDuration(s)
}
