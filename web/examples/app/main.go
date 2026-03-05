package main

import (
	"fmt"
	"os"
)

func main() {
	env := os.Getenv("ENCRYPTED_SECRET")
	fmt.Println("Env", env)
}
