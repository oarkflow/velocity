package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := loadDotEnvIfPresent(".env"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load .env: %v\n", err)
		os.Exit(1)
	}

	v, ok := os.LookupEnv("ENV_SECRET")
	if !ok || strings.TrimSpace(v) == "" {
		fmt.Fprintln(os.Stderr, "ENV_SECRET is not set")
		os.Exit(1)
	}

	fmt.Printf("ENV_SECRET=%s\n", v)
	if v == "your-32-byte-secrets-here" {
		fmt.Println("source=.env placeholder")
	} else {
		fmt.Println("source=runtime override (e.g., secretr exec vault value)")
	}
}

func loadDotEnvIfPresent(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		k, v, ok := splitEnvLine(line)
		if !ok {
			continue
		}

		if _, exists := os.LookupEnv(k); exists {
			continue
		}
		_ = os.Setenv(k, v)
	}
	return s.Err()
}

func splitEnvLine(line string) (key, value string, ok bool) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	key = strings.TrimSpace(parts[0])
	if key == "" {
		return "", "", false
	}

	value = strings.TrimSpace(parts[1])
	value = strings.Trim(value, "\"'")
	return key, value, true
}
