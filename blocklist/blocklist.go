package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type Request struct {
	IP string `json:"ip" binding:"required,ip"`
}

type Response struct {
	Found bool   `json:"found"`
	Error string `json:"error,omitempty"`
}

var (
	blockedIPs    = make(map[string]struct{})
	blocklistMu   sync.RWMutex
	blocklistPath string
	serverAddress string
	lastModTime   time.Time
)

func init() {
	// Load environment variables
	blocklistPath = os.Getenv("BLOCKLIST_PATH")
	if blocklistPath == "" {
		blocklistPath = "blocklist.txt" // Default path
	}

	serverAddress = os.Getenv("SERVER_ADDRESS")
	if serverAddress == "" {
		serverAddress = ":8080" // Default address
	}
}

func loadBlocklist() error {
	file, err := os.Open(blocklistPath)
	if err != nil {
		return err
	}

	defer file.Close()

	tempBlockedIPs := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Ignore empty lines and comments
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		tempBlockedIPs[line] = struct{}{}
	}

	if err = scanner.Err(); err != nil {
		return err
	}

	// Atomically update the new state of the blocklist
	blocklistMu.Lock()

	blockedIPs = tempBlockedIPs

	blocklistMu.Unlock()

	return nil
}

func checkAndUpdateBlocklist() error {
	fileInfo, err := os.Stat(blocklistPath)
	if err != nil {
		return err
	}

	// Check if the blocklist file has been modified
	if fileInfo.ModTime().After(lastModTime) {
		if err := loadBlocklist(); err != nil {
			return err
		}

		lastModTime = fileInfo.ModTime()
	}

	return nil
}

func main() {
	r := gin.Default()

	r.SetTrustedProxies(nil)

	// Initial load
	if err := checkAndUpdateBlocklist(); err != nil {
		fmt.Println("Error loading initial blocklist:", err.Error())
	}

	// Periodically check for updates, e.g., every 60 seconds
	go func() {
		for {
			if err := checkAndUpdateBlocklist(); err != nil {
				fmt.Println("Error checking/updating blocklist:", err.Error())
			}

			time.Sleep(time.Minute)
		}
	}()

	r.POST("/check", func(c *gin.Context) {
		var req Request
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, Response{Error: "Invalid input"})

			return
		}

		blocklistMu.RLock()

		_, found := blockedIPs[req.IP]

		blocklistMu.RUnlock()

		c.JSON(200, Response{Found: found})
	})

	if err := r.Run(serverAddress); err != nil {
		fmt.Println("Error starting the server:", err.Error())
	}
}
