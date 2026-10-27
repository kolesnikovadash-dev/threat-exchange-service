package apperrors

import "errors"

var (
	ErrInvalidInput = errors.New("invalid input")
	ErrNotFound     = errors.New("threat not found")
	ErrConflict     = errors.New("threat already exists or metadata conflicts")
)
