package threat

import (
	"context"

	"threat-exchange-service/internal/models"
)

type Repository interface {
	GetByMD5(ctx context.Context, md5 string) (models.Threat, error)
	Create(ctx context.Context, input models.ThreatInput) (models.Threat, error)
	Update(ctx context.Context, input models.ThreatInput) (models.Threat, error)
}

type Config struct {
	Repository Repository
}

type Usecase struct {
	repo Repository
}

func New(cfg Config) *Usecase { return &Usecase{repo: cfg.Repository} }

func (u *Usecase) GetByMD5(ctx context.Context, md5 string) (models.Threat, error) {
	md5, err := normalizeMD5(md5)
	if err != nil {
		return models.Threat{}, err
	}
	return u.repo.GetByMD5(ctx, md5)
}

func (u *Usecase) Create(ctx context.Context, input models.ThreatInput) (models.Threat, error) {
	if err := validateInput(&input); err != nil {
		return models.Threat{}, err
	}
	return u.repo.Create(ctx, input)
}

func (u *Usecase) Update(ctx context.Context, md5 string, input models.ThreatInput) (models.Threat, error) {
	input.MD5 = md5
	if err := validateInput(&input); err != nil {
		return models.Threat{}, err
	}
	return u.repo.Update(ctx, input)
}
