package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/mrinjamul/go-jwt-rest-api/models"
)

// RespondWithError returns
func RespondWithError(w http.ResponseWriter, status int, error models.Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

// ResponseJSON returns
func ResponseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

// GenerateToken returns
func GenerateToken(user models.User) (string, error) {
	var err error
	secret := os.Getenv("SECRET")
	// header.payload.secret
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "users",
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatalln(err)
	}

	return tokenString, nil
}
