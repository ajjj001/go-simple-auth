# go-simple-auth
Simple Authentication and Role-based Authorisation In Go

```go
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
```
