package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrTokenRequired      = errors.New("token required")
	ErrTokenBlacklisted   = errors.New("token blacklisted")
	ErrInvalidRole        = errors.New("invalid role")
)

type CredentialsVerifier interface {
	ValidateUser(email string, password string, r *http.Request) error
	AddClaims(email string, r *http.Request) (map[string]interface{}, error)
	ValidateRefreshToken(email string, refreshToken string, r *http.Request) error
	Finalize(email string, oldRefreshToken string, newAccessToken string, newRefreshToken string, r *http.Request) error
}

type Verifier struct{}

func (v *Verifier) ValidateUser(email string, password string, r *http.Request) error {
	if email == "admin@admin.com" && password == "admin" {
		return nil
	}
	return ErrInvalidCredentials
}

func (v *Verifier) AddClaims(email string, r *http.Request) (map[string]interface{}, error) {
	return map[string]interface{}{
		"email": email,
		"role":  []string{"admin", "user"},
	}, nil
}

var blacklistedTokens = []string{"b-1", "b-2", "b-3"}

func (v *Verifier) ValidateRefreshToken(email string, refreshToken string, r *http.Request) error {
	for _, blackListedToken := range blacklistedTokens {
		if refreshToken == blackListedToken {
			return ErrTokenBlacklisted
		}
	}
	return nil
}

func (v *Verifier) Finalize(email string, oldRefreshToken string, newAccessToken string, newRefreshToken string, r *http.Request) error {
	if oldRefreshToken != "" {
		blacklistedTokens = append(blacklistedTokens, oldRefreshToken)
	}
	return nil
}

type BearerServer struct {
	AccessTokenSecretKey  string
	RefreshTokenSecretKey string
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	verifier              CredentialsVerifier
}

func (bs *BearerServer) GetToken(w http.ResponseWriter, r *http.Request) {

	email := r.FormValue("email")
	password := r.FormValue("password")

	if err := bs.verifier.ValidateUser(email, password, r); err != nil {
		renderJSON(w, nil, http.StatusUnauthorized, err)
		return
	}

	claims, err := bs.verifier.AddClaims(email, r)
	if err != nil {
		renderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	token, err := CreateToken(email, bs.AccessTokenSecretKey, bs.AccessTokenTTL, claims)
	if err != nil {
		renderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	refreshToken, err := CreateToken(email, bs.RefreshTokenSecretKey, bs.RefreshTokenTTL, claims)
	if err != nil {
		renderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	err = bs.verifier.Finalize(email, "", token, refreshToken, r)
	if err != nil {
		renderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	renderJSON(w, SuccessResponse{
		AccessToken:  token,
		TokenType:    "Bearer",
		ExpiresIn:    bs.AccessTokenTTL.Seconds(),
		RefreshToken: refreshToken,
	}, http.StatusOK, nil)

}

func (bs *BearerServer) RefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		renderJSON(w, nil, http.StatusUnauthorized, ErrTokenRequired)
		return
	}

	err := bs.verifier.ValidateRefreshToken("", refreshToken, r)
	if err != nil {
		renderJSON(w, nil, http.StatusUnauthorized, err)
		return
	}

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrTokenInvalid
		}

		return []byte(bs.RefreshTokenSecretKey), nil
	})

	if err != nil {
		renderJSON(w, nil, http.StatusUnauthorized, err)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["email"].(string)
		claims, err := bs.verifier.AddClaims(email, r)
		if err != nil {
			renderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		newToken, err := CreateToken(email, bs.AccessTokenSecretKey, bs.AccessTokenTTL, claims)
		if err != nil {
			renderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		newRefreshToken, err := CreateToken(email, bs.RefreshTokenSecretKey, bs.RefreshTokenTTL, claims)
		if err != nil {
			renderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		err = bs.verifier.Finalize(email, refreshToken, newToken, newRefreshToken, r)
		if err != nil {
			renderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		renderJSON(w, SuccessResponse{
			AccessToken:  newToken,
			TokenType:    "Bearer",
			ExpiresIn:    bs.AccessTokenTTL.Seconds(),
			RefreshToken: newRefreshToken,
		}, http.StatusOK, nil)
	}
}

func CreateToken(email string, secretKey string, ttl time.Duration, claims map[string]interface{}) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(ttl).Unix(),
	})

	for key, value := range claims {
		token.Claims.(jwt.MapClaims)[key] = value
	}

	return token.SignedString([]byte(secretKey))
}

func renderJSON(w http.ResponseWriter, data interface{}, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err != nil {
		w.Write([]byte(`{"error":"` + err.Error() + `"}`))
		return
	}
	json.NewEncoder(w).Encode(data)
}

type SuccessResponse struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    float64 `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
}

type BearerAuthentication struct {
	secretKey string
}

func (ba *BearerAuthentication) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") || len(authHeader) < 8 {
			renderJSON(w, nil, http.StatusUnauthorized, ErrTokenRequired)
			return
		}

		authHeader = authHeader[7:]

		token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrTokenInvalid
			}

			return []byte(ba.secretKey), nil
		})

		if err != nil {
			renderJSON(w, nil, http.StatusUnauthorized, err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			next(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
		}
	}
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	renderJSON(w, map[string]interface{}{
		"claims": r.Context().Value(claimsKey),
	}, http.StatusOK, nil)
}

type key int

const (
	claimsKey key = iota
)

func main() {
	bs := &BearerServer{
		AccessTokenSecretKey:  "access",
		RefreshTokenSecretKey: "refresh",
		AccessTokenTTL:        15 * time.Minute,
		RefreshTokenTTL:       24 * time.Hour,
		verifier:              &Verifier{},
	}

	http.HandleFunc("/token", bs.GetToken)
	http.HandleFunc("/refresh", bs.RefreshToken)

	ba := &BearerAuthentication{
		secretKey: "access",
	}

	http.HandleFunc("/protected", ba.Authenticate(protectedEndpoint))

	http.ListenAndServe(":8080", nil)
}
