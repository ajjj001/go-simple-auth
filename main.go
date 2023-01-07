package main

import (
	"net/http"
	"time"

	"github.com/ajjj001/go-simple-auth/errors"
	"github.com/ajjj001/go-simple-auth/helpers"
	"github.com/ajjj001/go-simple-auth/models"
	"github.com/ajjj001/go-simple-auth/services"
)

type Verifier struct{}

func (v *Verifier) GetUserData(email string, r *http.Request) (any, error) {
	for _, u := range models.GetFakeUsers() {
		if u.Email == email {
			return u, nil
		}
	}

	return nil, errors.ErrInvalidCredentials
}

func (v *Verifier) ValidateUser(email string, password string, data any, r *http.Request) error {
	user := data.(models.User)
	if user.Password == password && user.Verified {
		return nil
	}

	return errors.ErrInvalidCredentials
}

func (v *Verifier) AddClaims(email string, data any, r *http.Request) (map[string]any, error) {
	user := data.(models.User)
	return map[string]any{
		"id":    user.ID,
		"roles": user.Roles,
	}, nil
}

var blacklistedTokens = []string{"b-1", "b-2", "b-3"}

func (v *Verifier) ValidateRefreshToken(email string, refreshToken string, data any, r *http.Request) error {
	user := data.(models.User)
	if !user.Verified {
		return errors.ErrInvalidCredentials
	}

	for _, blackListedToken := range blacklistedTokens {
		if refreshToken == blackListedToken {
			return errors.ErrInvalidCredentials
		}
	}

	return nil
}

func (v *Verifier) Finalize(email string, oldRefreshToken string, newAccessToken string, newRefreshToken string, data any, r *http.Request) error {
	if oldRefreshToken != "" {
		blacklistedTokens = append(blacklistedTokens, oldRefreshToken)
	}
	return nil
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	claims, ok := helpers.GetClaims(r)
	if !ok {
		helpers.RenderJSON(w, nil, http.StatusUnauthorized, errors.ErrTokenRequired)
		return
	}

	helpers.RenderJSON(w, map[string]any{
		"claims": claims,
	}, http.StatusOK, nil)
}

func adminEndpoint(w http.ResponseWriter, r *http.Request) {
	claims, ok := helpers.GetClaims(r)
	if !ok {
		helpers.RenderJSON(w, nil, http.StatusUnauthorized, errors.ErrTokenRequired)
		return
	}

	helpers.RenderJSON(w, map[string]any{
		"claims": claims,
	}, http.StatusOK, nil)
}

func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := helpers.GetClaims(r)
		if !ok {
			helpers.RenderJSON(w, nil, http.StatusUnauthorized, errors.ErrTokenRequired)
			return
		}

		roles := claims["roles"].([]interface{})
		for _, role := range roles {
			if role == "admin" {
				next(w, r)
				return
			}
		}

		helpers.RenderJSON(w, nil, http.StatusForbidden, errors.ErrUnauthorized)
	}
}

func main() {
	grantService := &services.GrantService{
		AccessTokenSecretKey:  "access",
		RefreshTokenSecretKey: "refresh",
		AccessTokenTTL:        15 * time.Minute,
		RefreshTokenTTL:       24 * time.Hour,
		Verifier:              &Verifier{},
	}

	http.HandleFunc("/token", grantService.GetToken)
	http.HandleFunc("/refresh", grantService.RefreshToken)

	authService := &services.AuthService{
		SecretKey: "access",
	}

	http.HandleFunc("/protected", authService.Authenticate(protectedEndpoint))
	http.HandleFunc("/admin", authService.Authenticate(adminOnly(adminEndpoint)))

	http.ListenAndServe(":8080", nil)
}
