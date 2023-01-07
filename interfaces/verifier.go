package interfaces

import (
	"net/http"
)

type Verifier interface {
	GetUserData(email string, r *http.Request) (any, error)
	ValidateUser(email string, password string, data any, r *http.Request) error
	AddClaims(email string, data any, r *http.Request) (map[string]any, error)
	ValidateRefreshToken(email string, refreshToken string, data any, r *http.Request) error
	Finalize(email string, oldRefreshToken string, newAccessToken string, newRefreshToken string, data any, r *http.Request) error
}
