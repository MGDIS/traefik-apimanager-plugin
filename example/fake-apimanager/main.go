package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"time"
)

type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

func generateRandomToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Generate a random access token
	accessToken := generateRandomToken(32) // 32 characters long

	// Create the response
	response := AuthResponse{
		AccessToken: accessToken,
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")

	// Encode the response as JSON and send it
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func main() {
	http.HandleFunc("/auth", authHandler)

	// Start the server
	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
