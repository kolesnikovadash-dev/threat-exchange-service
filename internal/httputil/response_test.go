package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteOK(t *testing.T) {
	cases := []struct {
		name   string
		status int
		data   any
	}{
		{"ok", http.StatusOK, map[string]string{"name": "Trojan.Test"}},
		{"created", http.StatusCreated, map[string]string{"md5": "d41d8cd98f00b204e9800998ecf8427e"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteOK(rec, tc.status, tc.data)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q", ct)
			}
			var response map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if _, ok := response["data"]; ok {
				t.Fatal("unexpected response wrapper")
			}
			if len(response) != 1 {
				t.Fatalf("unexpected response: %+v", response)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		message string
		details string
	}{
		{"invalid request", http.StatusBadRequest, "Invalid request", "invalid md5"},
		{"missing threat", http.StatusNotFound, "Threat not found", "missing hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			WriteError(rec, tc.status, tc.message, tc.details)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
			var response struct {
				Message string `json:"message"`
				Details string `json:"details"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Message != tc.message || response.Details != tc.details {
				t.Errorf("response = %+v", response)
			}
		})
	}
}
