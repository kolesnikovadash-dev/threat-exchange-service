package threat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/apperrors"
	threatdto "github.com/kolesnikovadash-dev/threat-exchange-service/internal/dto/threat"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/httputil"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/models"
)

const maxBodySize = 64 * 1024

type ThreatUsecase interface {
	GetByMD5(context.Context, string) (models.Threat, error)
	Create(context.Context, models.ThreatInput) (models.Threat, error)
	Update(context.Context, string, models.ThreatInput) (models.Threat, error)
}

type Handler struct {
	threat ThreatUsecase
}

func NewHandler(threat ThreatUsecase) *Handler {
	return &Handler{threat: threat}
}

func (h *Handler) GetByMD5(w http.ResponseWriter, r *http.Request) {
	result, err := h.threat.GetByMD5(r.Context(), r.PathValue("md5"))
	if err != nil {
		writeDomainError(w, err)
		return
	}
	httputil.WriteOK(w, http.StatusOK, result)
}

func (h *Handler) CreateThreat(w http.ResponseWriter, r *http.Request) {
	var request threatdto.CreateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	result, err := h.threat.Create(r.Context(), models.ThreatInput{
		MD5: request.MD5, Name: request.Name,
		Description: request.Description, Severity: request.Severity, ThreatType: request.ThreatType,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	httputil.WriteOK(w, http.StatusCreated, result)
}

func (h *Handler) UpdateThreat(w http.ResponseWriter, r *http.Request) {
	var request threatdto.UpdateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}
	result, err := h.threat.Update(r.Context(), r.PathValue("md5"), models.ThreatInput{
		Name: request.Name, Description: request.Description,
		Severity: request.Severity, ThreatType: request.ThreatType,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}
	httputil.WriteOK(w, http.StatusOK, result)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type must be application/json")
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if len(raw) == 0 || raw[0] != '{' {
		return errors.New("request body must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	for key, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("field %s cannot be null", key)
		}
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(dest); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apperrors.ErrInvalidInput):
		httputil.WriteError(w, http.StatusBadRequest, "Invalid request", err.Error())
	case errors.Is(err, apperrors.ErrNotFound):
		httputil.WriteError(w, http.StatusNotFound, "Threat not found", err.Error())
	case errors.Is(err, apperrors.ErrConflict):
		httputil.WriteError(w, http.StatusConflict, "Threat conflict", err.Error())
	default:
		httputil.WriteError(w, http.StatusInternalServerError, "Internal server error", "unexpected server failure")
	}
}
