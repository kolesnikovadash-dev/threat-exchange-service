//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/app"
)

func TestAPIWithPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	var dbName string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dbName, "_test") {
		t.Fatalf("refusing to run integration tests against non-test database %q", dbName)
	}

	// применяем миграции, если тестовая база ещё не подготовлена
	var schemaReady bool
	err = pool.QueryRow(ctx, `
        SELECT to_regclass('public.threat') IS NOT NULL
           AND to_regclass('public.file_hash') IS NOT NULL
    `).Scan(&schemaReady)
	if err != nil {
		t.Fatal(err)
	}
	if !schemaReady {
		migration, err := os.ReadFile("../../db/migrations/000001_init.up.sql")
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range strings.Split(string(migration), ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := pool.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
	}

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	md5A := hex.EncodeToString(random[:16])
	md5B := hex.EncodeToString(random[16:])
	name := fmt.Sprintf("Integration.Test.%s", md5A)
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_, _ = pool.Exec(cleanCtx, `DELETE FROM file_hash WHERE md5 = ANY($1)`, []string{md5A, md5B})
		_, _ = pool.Exec(cleanCtx, `DELETE FROM threat WHERE name = $1`, name)
	})

	srv := httptest.NewServer(app.New(pool))
	defer srv.Close()
	client := srv.Client()
	request := func(method, path string, data any, want int) map[string]any {
		t.Helper()
		var payload []byte
		if data != nil {
			payload, err = json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, srv.URL+path, bytes.NewReader(payload))
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		if data != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, reqErr := client.Do(req)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: got %d want %d: %+v", method, path, resp.StatusCode, want, body)
		}
		return body
	}

	cases := []struct {
		name, method, path string
		payload            map[string]any
		status             int
		wantSeverity       string
	}{
		{"create first md5", http.MethodPost, "/info", map[string]any{"md5": md5A, "name": name, "severity": "medium", "threat_type": "trojan"}, http.StatusCreated, "medium"},
		{"create second md5", http.MethodPost, "/info", map[string]any{"md5": md5B, "name": name}, http.StatusCreated, "medium"},
		{"duplicate md5", http.MethodPost, "/info", map[string]any{"md5": md5A, "name": name}, http.StatusConflict, ""},
		{"update shared definition", http.MethodPut, "/info/" + md5A, map[string]any{"name": name, "severity": "critical"}, http.StatusOK, "critical"},
		{"check second md5", http.MethodGet, "/info/" + md5B, nil, http.StatusOK, "critical"},
		{"invalid md5", http.MethodGet, "/info/invalid", nil, http.StatusBadRequest, ""},
		{"unknown md5", http.MethodGet, "/info/00000000000000000000000000000000", nil, http.StatusNotFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := request(tc.method, tc.path, tc.payload, tc.status)
			if tc.wantSeverity != "" && result["severity"] != tc.wantSeverity {
				t.Fatalf("severity=%v want=%s", result["severity"], tc.wantSeverity)
			}
		})
	}
}
