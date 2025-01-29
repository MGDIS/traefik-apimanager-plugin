package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
)

type Headers struct {
	Authorization           string `json:"Authorization,omitempty"`
	XForwardedAuthorization string `json:"X-Forwarded-Authorization,omitempty"`
}

type Response struct {
	Message string  `json:"message"`
	Headers Headers `json:"headers"`
}

type Server struct {
	logger *slog.Logger
}

func (s *Server) demoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	s.logger.Info("Request received with headers", "headers", r.Header)

	// Create the response
	response := Response{
		Message: "Hello world !",
		Headers: Headers{
			Authorization:           r.Header.Get("Authorization"),
			XForwardedAuthorization: r.Header.Get("X-Forwarded-Authorization"),
		},
	}

	// Set the response header to application/json
	w.Header().Set("Content-Type", "application/json")

	// Encode the response as JSON and send it
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	server := &Server{logger: logger}

	http.HandleFunc("/demo", server.demoHandler)
	http.HandleFunc("/demo/{id}", server.demoHandler)
	http.HandleFunc("/foobar", server.demoHandler)
	http.HandleFunc("/foobar/{id}", server.demoHandler)

	logger.Info("Server is starting on port 8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		logger.Error("Failed to start server", "error", err.Error())
		panic(err)
	}
}
