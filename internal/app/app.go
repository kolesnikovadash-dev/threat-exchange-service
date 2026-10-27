package app

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/server"
)

func New(pool *pgxpool.Pool) http.Handler {
	cfg := CreateConfig(pool)
	return server.New(server.Config{
		GetByMD5: cfg.Handlers.Threat.GetByMD5,
		Create:   cfg.Handlers.Threat.CreateThreat,
		Update:   cfg.Handlers.Threat.UpdateThreat,
	})
}
