// Copyright (C) 2024 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
)

func init() {
	// Set log format to include colors
	term := os.Getenv("TERM")

	if term == "xterm-256color" {
		log.SetFlags(0)
		log.SetOutput(color.Output)
	} else {
		log.SetFlags(log.LstdFlags)
	}
}

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

	color.Yellow("Loading IP list done")

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

func loggingMiddleware(c *gin.Context) {
	startTime := time.Now()

	// Log the request body
	var requestBodyBytes []byte

	if c.Request.Body != nil {
		requestBodyBytes, _ = io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(bytes.NewBuffer(requestBodyBytes)) // Reset request body for further use
	}

	color.Cyan("Request: %s %s %s\n", c.Request.Method, c.Request.URL.Path, c.Request.Proto)
	color.Cyan("Request Body: %s\n", string(requestBodyBytes))

	// Capture the response body
	responseBody := new(bytes.Buffer)
	c.Writer = &responseBodyWriter{
		ResponseWriter: c.Writer,
		body:           responseBody,
	}

	// Process request
	c.Next()

	// Log the response body
	color.Cyan("Response: %d %s\n", c.Writer.Status(), http.StatusText(c.Writer.Status()))
	color.Cyan("Response Body: %s\n", responseBody.String())
	color.Cyan("Duration: %v\n", time.Since(startTime))
}

type responseBodyWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w responseBodyWriter) Write(b []byte) (int, error) {
	w.body.Write(b)

	return w.ResponseWriter.Write(b)
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	r.Use(gin.Logger())
	r.SetTrustedProxies(nil)
	r.Use(loggingMiddleware)

	// Initial load
	if err := checkAndUpdateBlocklist(); err != nil {
		color.Red("Error loading initial blocklist:", err.Error())
	}

	// Periodically check for updates, e.g., every 60 seconds
	go func() {
		for {
			if err := checkAndUpdateBlocklist(); err != nil {
				color.Red("Error checking/updating blocklist:", err.Error())
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
		color.Red("Error starting the server:", err.Error())
	}
}
