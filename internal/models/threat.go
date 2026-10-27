package models

import "time"

type Threat struct {
	MD5         string    `json:"md5"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	ThreatType  string    `json:"threat_type"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type ThreatInput struct {
	MD5         string
	Name        string
	Description *string
	Severity    *string
	ThreatType  *string
}
