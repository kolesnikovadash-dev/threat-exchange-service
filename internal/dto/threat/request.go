package threat

type ThreatFields struct {
	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`
	Severity    *string `json:"severity,omitempty"`
	ThreatType  *string `json:"threat_type,omitempty"`
}

type CreateRequest struct {
	MD5 string `json:"md5"`
	ThreatFields
}

type UpdateRequest = ThreatFields
