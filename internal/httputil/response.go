package httputil

import (
	"encoding/json"
	"net/http"
)

type errorResponse struct {
	Message string `json:"message"`
	Details string `json:"details"`
}

func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func WriteOK(w http.ResponseWriter, status int, data any) {
	WriteJSON(w, status, data)
}

func WriteError(w http.ResponseWriter, status int, message, details string) {
	WriteJSON(w, status, errorResponse{Message: message, Details: details})
}
