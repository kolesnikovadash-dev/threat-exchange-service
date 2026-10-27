package threat

type CreateRequest struct {
	MD5         string  `json:"md5"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	ThreatType  *string `json:"threat_type,omitempty"`
}

type UpdateRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	ThreatType  *string `json:"threat_type,omitempty"`
}
