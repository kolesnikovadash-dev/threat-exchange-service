package httputil

import (
	"encoding/json"
	"net/http"
)

type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details"`
}

func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func WriteOK(w http.ResponseWriter, data any) {
	WriteJSON(w, http.StatusOK, data)
}

func WriteError(w http.ResponseWriter, status int, message, details string) {
	WriteJSON(w, status, ErrorResponse{Message: message, Details: details})
}
