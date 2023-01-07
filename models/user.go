package models

type User struct {
	ID       int      `json:"id"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Roles    []string `json:"role"`
	Verified bool     `json:"verified"`
}

func GetFakeUsers() []User {
	users := []User{
		{
			ID:       1,
			Email:    "admin@gmail.com",
			Password: "admin",
			Roles:    []string{"admin", "user"},
			Verified: true,
		},
		{
			ID:       2,
			Email:    "user1@gmail.com",
			Password: "user1",
			Roles:    []string{"user"},
			Verified: true,
		},
		{
			ID:       3,
			Email:    "user2@gmail.com",
			Password: "user2",
			Roles:    []string{"user"},
			Verified: true,
		},
	}

	return users
}
