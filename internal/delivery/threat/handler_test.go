package threat_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/apperrors"
	delivery "github.com/kolesnikovadash-dev/threat-exchange-service/internal/delivery/threat"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/models"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/server"
	usecase "github.com/kolesnikovadash-dev/threat-exchange-service/internal/usecase/threat"
)

type repoStub struct{ err error }

func (f *repoStub) GetByMD5(_ context.Context, md5 string) (models.Threat, error) {
	if f.err != nil {
		return models.Threat{}, f.err
	}
	return models.Threat{MD5: md5, Name: "Test"}, nil
}
func (f *repoStub) Create(_ context.Context, in models.ThreatInput) (models.Threat, error) {
	if f.err != nil {
		return models.Threat{}, f.err
	}
	return models.Threat{MD5: in.MD5, Name: in.Name}, nil
}
func (f *repoStub) Update(_ context.Context, in models.ThreatInput) (models.Threat, error) {
	if f.err != nil {
		return models.Threat{}, f.err
	}
	return models.Threat{MD5: in.MD5, Name: in.Name}, nil
}

func perform(method, path, payload string, dbErr error) *httptest.ResponseRecorder {
	handler := delivery.NewHandler(usecase.NewThreatUsecase(&repoStub{err: dbErr}))
	api := server.New(server.Config{GetByMD5: handler.GetByMD5, Create: handler.CreateThreat, Update: handler.UpdateThreat})
	req := httptest.NewRequest(method, path, strings.NewReader(payload))
	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	return w
}

func TestCreateReturns201(t *testing.T) {
	cases := []struct {
		name    string
		md5     string
		wantMD5 string
	}{
		{name: "uppercase", md5: "D41D8CD98F00B204E9800998ECF8427E", wantMD5: "d41d8cd98f00b204e9800998ecf8427e"},
		{name: "lowercase", md5: "d41d8cd98f00b204e9800998ecf8427e", wantMD5: "d41d8cd98f00b204e9800998ecf8427e"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"md5":"` + tc.md5 + `","name":"Test"}`
			w := perform(http.MethodPost, "/info", body, nil)
			if w.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var data models.Threat
			if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
				t.Fatal(err)
			}
			if data.MD5 != tc.wantMD5 {
				t.Fatalf("md5=%q want=%q", data.MD5, tc.wantMD5)
			}
		})
	}
}

func TestHTTPValidationAndErrors(t *testing.T) {
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	cases := []struct {
		name, method, path, body string
		dbErr                    error
		status                   int
	}{
		{"invalid md5", http.MethodGet, "/info/not-md5", "", nil, http.StatusBadRequest},
		{"unknown md5", http.MethodGet, "/info/" + md5, "", apperrors.ErrNotFound, http.StatusNotFound},
		{"broken json", http.MethodPost, "/info", `{broken`, nil, http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/info", `{"md5":"` + md5 + `","name":"Test","unrecognized":1}`, nil, http.StatusBadRequest},
		{"null optional", http.MethodPost, "/info", `{"md5":"` + md5 + `","name":"Test","severity":null}`, nil, http.StatusBadRequest},
		{"null required", http.MethodPost, "/info", `{"md5":null,"name":"Test"}`, nil, http.StatusBadRequest},
		{"null body", http.MethodPost, "/info", `null`, nil, http.StatusBadRequest},
		{"array body", http.MethodPost, "/info", `[]`, nil, http.StatusBadRequest},
		{"invalid type", http.MethodPost, "/info", `{"md5":"` + md5 + `","name":42}`, nil, http.StatusBadRequest},
		{"missing name", http.MethodPost, "/info", `{"md5":"` + md5 + `"}`, nil, http.StatusBadRequest},
		{"duplicate md5", http.MethodPost, "/info", `{"md5":"` + md5 + `","name":"Test"}`, apperrors.ErrConflict, http.StatusConflict},
		{"unknown update", http.MethodPut, "/info/" + md5, `{"name":"Test"}`, apperrors.ErrNotFound, http.StatusNotFound},
		{"null update", http.MethodPut, "/info/" + md5, `{"name":"Test","description":null}`, nil, http.StatusBadRequest},
		{"internal error", http.MethodGet, "/info/" + md5, "", errors.New("private db details"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := perform(tc.method, tc.path, tc.body, tc.dbErr)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("invalid JSON response: %v", err)
			}
			if strings.Contains(w.Body.String(), "private db details") {
				t.Error("internal error leaked to client")
			}
		})
	}
}

func TestHTTPPositiveResponses(t *testing.T) {
	const md5 = "d41d8cd98f00b204e9800998ecf8427e"
	cases := []struct {
		name, method, path, body string
		status                   int
	}{
		{"health", http.MethodGet, "/health", "", http.StatusOK},
		{"get", http.MethodGet, "/info/" + md5, "", http.StatusOK},
		{"update", http.MethodPut, "/info/" + md5, `{"name":"Test"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := perform(tc.method, tc.path, tc.body, nil)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}
