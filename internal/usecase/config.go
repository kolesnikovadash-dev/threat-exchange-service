package usecase

import "github.com/kolesnikovadash-dev/threat-exchange-service/internal/usecase/threat"

type Config struct {
	Threat *threat.ThreatUsecase
}

func CreateConfig(threats threat.ThreatRepository) *Config {
	return &Config{Threat: threat.NewThreatUsecase(threats)}
}
