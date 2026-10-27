package app

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	threatDelivery "threat-exchange-service/internal/delivery/threat"
	threatRepository "threat-exchange-service/internal/repository/threat"
	"threat-exchange-service/internal/server"
	threatUsecase "threat-exchange-service/internal/usecase/threat"
)

func New(pool *pgxpool.Pool) http.Handler {
	repo := threatRepository.NewPostgres(threatRepository.Config{Pool: pool})
	usecase := threatUsecase.New(threatUsecase.Config{Repository: repo})
	handler := threatDelivery.NewHandler(threatDelivery.Config{Usecase: usecase})
	return server.New(server.Config{
		GetByMD5: handler.GetByMD5,
		Create:   handler.Create,
		Update:   handler.Update,
	})
}
