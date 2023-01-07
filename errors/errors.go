package errors

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrTokenRequired      = errors.New("token required")
	ErrTokenBlacklisted   = errors.New("token blacklisted")
	ErrInvalidRole        = errors.New("invalid role")
	ErrUnauthorized       = errors.New("unauthorized")
)
