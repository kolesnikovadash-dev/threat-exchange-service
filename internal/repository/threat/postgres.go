package threat

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/apperrors"
	"github.com/kolesnikovadash-dev/threat-exchange-service/internal/models"
)

const getByMD5SQL = `
SELECT f.md5, t.name, t.description, t.severity, t.threat_type,
       f.created_at, GREATEST(f.updated_at, t.updated_at)
FROM file_hash f
JOIN threat t ON t.id = f.threat_id
WHERE f.md5 = $1`

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func readThreat(ctx context.Context, q querier, md5 string) (models.Threat, error) {
	var result models.Threat
	err := q.QueryRow(ctx, getByMD5SQL, md5).Scan(
		&result.MD5, &result.Name, &result.Description, &result.Severity,
		&result.ThreatType, &result.CreatedAt, &result.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Threat{}, apperrors.ErrNotFound
	}
	if err != nil {
		return models.Threat{}, fmt.Errorf("read threat: %w", err)
	}
	return result, nil
}

func (r *PostgresRepository) GetByMD5(ctx context.Context, md5 string) (models.Threat, error) {
	return readThreat(ctx, r.pool, md5)
}

func (r *PostgresRepository) Create(ctx context.Context, input models.ThreatInput) (models.Threat, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return models.Threat{}, fmt.Errorf("begin create: %w", err)
	}
	defer tx.Rollback(ctx)

	var threatID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO threat (name, description, severity, threat_type)
		VALUES ($1, COALESCE($2::text, ''), COALESCE($3::text, 'unknown'), COALESCE($4::text, 'other'))
		ON CONFLICT (name) DO NOTHING
		RETURNING id`, input.Name, input.Description, input.Severity, input.ThreatType,
	).Scan(&threatID)
	if errors.Is(err, pgx.ErrNoRows) {
		var description, severity, threatType string
		err = tx.QueryRow(ctx, `SELECT id, description, severity, threat_type FROM threat WHERE name = $1`, input.Name).
			Scan(&threatID, &description, &severity, &threatType)
		if err != nil {
			return models.Threat{}, fmt.Errorf("find threat definition: %w", err)
		}
		// не изменяем общие сведения об угрозе при добавлении нового хеша
		if (input.Description != nil && *input.Description != description) ||
			(input.Severity != nil && *input.Severity != severity) ||
			(input.ThreatType != nil && *input.ThreatType != threatType) {
			return models.Threat{}, fmt.Errorf("%w: metadata differs from existing threat definition", apperrors.ErrConflict)
		}
	} else if err != nil {
		return models.Threat{}, fmt.Errorf("insert threat definition: %w", err)
	}

	_, err = tx.Exec(ctx, `INSERT INTO file_hash (md5, threat_id) VALUES ($1, $2)`, input.MD5, threatID)
	if isUniqueViolation(err) {
		return models.Threat{}, fmt.Errorf("%w: md5 already exists", apperrors.ErrConflict)
	}
	if err != nil {
		return models.Threat{}, fmt.Errorf("insert file hash: %w", err)
	}
	result, err := readThreat(ctx, tx, input.MD5)
	if err != nil {
		return models.Threat{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Threat{}, fmt.Errorf("commit create: %w", err)
	}
	return result, nil
}

func (r *PostgresRepository) Update(ctx context.Context, input models.ThreatInput) (models.Threat, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return models.Threat{}, fmt.Errorf("begin update: %w", err)
	}
	defer tx.Rollback(ctx)

	// блокируем запись, чтобы параллельные обновления одного md5 не конфликтовали
	var oldID int64
	err = tx.QueryRow(ctx, `SELECT threat_id FROM file_hash WHERE md5 = $1 FOR UPDATE`, input.MD5).Scan(&oldID)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Threat{}, apperrors.ErrNotFound
	}
	if err != nil {
		return models.Threat{}, fmt.Errorf("lock file hash: %w", err)
	}

	var threatID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO threat (name, description, severity, threat_type)
		VALUES ($1, COALESCE($2::text, ''), COALESCE($3::text, 'unknown'), COALESCE($4::text, 'other'))
		ON CONFLICT (name) DO NOTHING
		RETURNING id`, input.Name, input.Description, input.Severity, input.ThreatType,
	).Scan(&threatID)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id FROM threat WHERE name = $1`, input.Name).Scan(&threatID)
		if err != nil {
			return models.Threat{}, fmt.Errorf("find threat definition: %w", err)
		}
		if input.Description != nil || input.Severity != nil || input.ThreatType != nil {
			// изменение общих сведений затрагивает все связанные хеши
			_, err = tx.Exec(ctx, `
				UPDATE threat SET
				  description = COALESCE($2::text, description),
				  severity = COALESCE($3::text, severity),
				  threat_type = COALESCE($4::text, threat_type),
				  updated_at = NOW()
				WHERE id = $1`, threatID, input.Description, input.Severity, input.ThreatType)
			if err != nil {
				return models.Threat{}, fmt.Errorf("update threat definition: %w", err)
			}
		}
	} else if err != nil {
		return models.Threat{}, fmt.Errorf("insert threat definition: %w", err)
	}

	_, err = tx.Exec(ctx, `UPDATE file_hash SET threat_id = $2, updated_at = NOW() WHERE md5 = $1`, input.MD5, threatID)
	if err != nil {
		return models.Threat{}, fmt.Errorf("update file hash: %w", err)
	}
	result, err := readThreat(ctx, tx, input.MD5)
	if err != nil {
		return models.Threat{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Threat{}, fmt.Errorf("commit update: %w", err)
	}
	return result, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
