package threat

import (
	"context"

	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/models"
)

type ThreatRepository interface {
	GetByMD5(ctx context.Context, md5 string) (models.Threat, error)
	Create(ctx context.Context, input models.ThreatInput) (models.Threat, error)
	Update(ctx context.Context, input models.ThreatInput) (models.Threat, error)
}

type ThreatUsecase struct {
	threats ThreatRepository
}

func NewThreatUsecase(threats ThreatRepository) *ThreatUsecase {
	return &ThreatUsecase{threats: threats}
}

func (u *ThreatUsecase) GetByMD5(ctx context.Context, md5 string) (models.Threat, error) {
	md5, err := normalizeMD5(md5)
	if err != nil {
		return models.Threat{}, err
	}
	return u.threats.GetByMD5(ctx, md5)
}

func (u *ThreatUsecase) Create(ctx context.Context, input models.ThreatInput) (models.Threat, error) {
	if err := validateInput(&input); err != nil {
		return models.Threat{}, err
	}
	return u.threats.Create(ctx, input)
}

func (u *ThreatUsecase) Update(ctx context.Context, md5 string, input models.ThreatInput) (models.Threat, error) {
	input.MD5 = md5
	if err := validateInput(&input); err != nil {
		return models.Threat{}, err
	}
	return u.threats.Update(ctx, input)
}
