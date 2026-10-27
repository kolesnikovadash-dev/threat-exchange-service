package threat

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"threat-exchange-service/internal/apperrors"
	"threat-exchange-service/internal/models"
)

var md5Pattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func normalizeMD5(raw string) (string, error) {
	if !md5Pattern.MatchString(raw) {
		return "", fmt.Errorf("%w: md5 must contain exactly 32 hexadecimal characters", apperrors.ErrInvalidInput)
	}
	return strings.ToLower(raw), nil
}

func validateInput(in *models.ThreatInput) error {
	var err error
	in.MD5, err = normalizeMD5(in.MD5)
	if err != nil {
		return err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > 255 {
		return fmt.Errorf("%w: name must contain 1 to 255 characters", apperrors.ErrInvalidInput)
	}
	if in.Description != nil {
		description := strings.TrimSpace(*in.Description)
		if utf8.RuneCountInString(description) > 2048 {
			return fmt.Errorf("%w: description is too long (max 2048 characters)", apperrors.ErrInvalidInput)
		}
		in.Description = &description
	}
	if in.Severity != nil {
		value := strings.ToLower(strings.TrimSpace(*in.Severity))
		switch value {
		case "unknown", "low", "medium", "high", "critical":
			in.Severity = &value
		default:
			return fmt.Errorf("%w: invalid severity", apperrors.ErrInvalidInput)
		}
	}
	if in.ThreatType != nil {
		value := strings.ToLower(strings.TrimSpace(*in.ThreatType))
		switch value {
		case "other", "trojan", "worm", "ransomware", "spyware":
			in.ThreatType = &value
		default:
			return fmt.Errorf("%w: invalid threat_type", apperrors.ErrInvalidInput)
		}
	}
	return nil
}
