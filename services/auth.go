package services

import (
	"context"
	"net/http"
	"strings"

	"github.com/ajjj001/go-simple-auth/errors"
	"github.com/ajjj001/go-simple-auth/helpers"
	"github.com/golang-jwt/jwt/v4"
)

type AuthService struct {
	SecretKey string
}

func (ba *AuthService) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") || len(authHeader) < 8 {
			helpers.RenderJSON(w, nil, http.StatusUnauthorized, errors.ErrTokenRequired)
			return
		}

		authHeader = authHeader[7:]

		token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.ErrTokenInvalid
			}

			return []byte(ba.SecretKey), nil
		})

		if err != nil {
			helpers.RenderJSON(w, nil, http.StatusUnauthorized, err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			next(w, r.WithContext(context.WithValue(r.Context(), helpers.ClaimsKey, claims)))
		}
	}
}
