package delivery

import "github.com/kolesnikovadash-dev/threat-exchange-service/internal/delivery/threat"

type Config struct {
	Threat *threat.Handler
}

func CreateConfig(threats threat.ThreatUsecase) *Config {
	return &Config{Threat: threat.NewHandler(threats)}
}
