package app

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/delivery"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/repository"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/usecase"
)

type Config struct {
	Repositories *repository.Config
	Usecases     *usecase.Config
	Handlers     *delivery.Config
}

func CreateConfig(pool *pgxpool.Pool) *Config {
	repos := repository.CreateConfig(pool)
	usecases := usecase.CreateConfig(repos.Threat)
	handlers := delivery.CreateConfig(usecases.Threat)

	return &Config{
		Repositories: repos,
		Usecases:     usecases,
		Handlers:     handlers,
	}
}
