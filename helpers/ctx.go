package helpers

import (
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

type key int

const ClaimsKey key = iota

func GetClaims(r *http.Request) (jwt.MapClaims, bool) {
	claims, ok := r.Context().Value(ClaimsKey).(jwt.MapClaims)
	return claims, ok
}
