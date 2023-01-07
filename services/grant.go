package services

import (
	"net/http"
	"time"

	"github.com/ajjj001/go-simple-auth/errors"
	"github.com/ajjj001/go-simple-auth/helpers"
	"github.com/ajjj001/go-simple-auth/interfaces"
	"github.com/ajjj001/go-simple-auth/responses"
	"github.com/golang-jwt/jwt/v4"
)

type GrantService struct {
	AccessTokenSecretKey  string
	RefreshTokenSecretKey string
	AccessTokenTTL        time.Duration
	RefreshTokenTTL       time.Duration
	Verifier              interfaces.Verifier
}

func (bs *GrantService) GetToken(w http.ResponseWriter, r *http.Request) {

	email := r.FormValue("email")
	password := r.FormValue("password")

	data, err := bs.Verifier.GetUserData(email, r)
	if err != nil {
		helpers.RenderJSON(w, nil, http.StatusUnauthorized, err)
		return
	}

	if err := bs.Verifier.ValidateUser(email, password, data, r); err != nil {
		helpers.RenderJSON(w, nil, http.StatusUnauthorized, err)
		return
	}

	claims, err := bs.Verifier.AddClaims(email, data, r)
	if err != nil {
		helpers.RenderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	token, refreshToken, err := CreateTokens(email, bs.AccessTokenSecretKey, bs.RefreshTokenSecretKey, bs.AccessTokenTTL, bs.RefreshTokenTTL, claims)
	if err != nil {
		helpers.RenderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	err = bs.Verifier.Finalize(email, "", token, refreshToken, data, r)
	if err != nil {
		helpers.RenderJSON(w, nil, http.StatusInternalServerError, err)
		return
	}

	helpers.RenderJSON(w, responses.Success{
		AccessToken:  token,
		TokenType:    "Bearer",
		ExpiresIn:    bs.AccessTokenTTL.Seconds(),
		RefreshToken: refreshToken,
	}, http.StatusOK, nil)

}

func (bs *GrantService) RefreshToken(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	if refreshToken == "" {
		helpers.RenderJSON(w, nil, http.StatusUnauthorized, errors.ErrTokenRequired)
		return
	}

	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.ErrTokenInvalid
		}

		return []byte(bs.RefreshTokenSecretKey), nil
	})

	if err != nil {
		helpers.RenderJSON(w, nil, http.StatusUnauthorized, err)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["email"].(string)
		data, err := bs.Verifier.GetUserData(email, r)
		if err != nil {
			helpers.RenderJSON(w, nil, http.StatusUnauthorized, err)
			return
		}

		if err := bs.Verifier.ValidateRefreshToken(email, refreshToken, data, r); err != nil {
			helpers.RenderJSON(w, nil, http.StatusUnauthorized, err)
			return
		}

		newClaims, err := bs.Verifier.AddClaims(email, data, r)
		if err != nil {
			helpers.RenderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		newAccessToken, newRefreshToken, err := CreateTokens(email, bs.AccessTokenSecretKey, bs.RefreshTokenSecretKey, bs.AccessTokenTTL, bs.RefreshTokenTTL, newClaims)
		if err != nil {
			helpers.RenderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		err = bs.Verifier.Finalize(email, refreshToken, newAccessToken, newRefreshToken, data, r)
		if err != nil {
			helpers.RenderJSON(w, nil, http.StatusInternalServerError, err)
			return
		}

		helpers.RenderJSON(w, responses.Success{
			AccessToken:  newAccessToken,
			TokenType:    "Bearer",
			ExpiresIn:    bs.AccessTokenTTL.Seconds(),
			RefreshToken: newRefreshToken,
		}, http.StatusOK, nil)
		return
	}

	helpers.RenderJSON(w, nil, http.StatusUnauthorized, errors.ErrTokenInvalid)
}

func CreateTokens(email string, accessSecretKey string, refreshSecretKey string, accessTokenTTL time.Duration, refreshTokenTTL time.Duration, claims map[string]any) (string, string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(accessTokenTTL).Unix(),
	})

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(refreshTokenTTL).Unix(),
	})

	for key, value := range claims {
		accessToken.Claims.(jwt.MapClaims)[key] = value
		refreshToken.Claims.(jwt.MapClaims)[key] = value
	}

	accessTokenString, err := accessToken.SignedString([]byte(accessSecretKey))
	if err != nil {
		return "", "", err
	}

	refreshTokenString, err := refreshToken.SignedString([]byte(refreshSecretKey))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}
