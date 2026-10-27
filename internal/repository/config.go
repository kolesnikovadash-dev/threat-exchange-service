package repository

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/repository/threat"
)

type Config struct {
	Threat *threat.PostgresRepository
}

func CreateConfig(pool *pgxpool.Pool) *Config {
	return &Config{Threat: threat.NewPostgresRepository(pool)}
}
