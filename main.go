package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/mrinjamul/go-jwt-rest-api/driver"
	"github.com/mrinjamul/go-jwt-rest-api/models"
	"github.com/mrinjamul/go-jwt-rest-api/utils"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db, _ = driver.ConnectDB()
	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")

	err := http.ListenAndServe(":8000", router)

	if err != nil {
		log.Fatal(err)
	}
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var errors models.Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		errors.Message = "Email is missing."
		utils.RespondWithError(w, http.StatusBadRequest, errors)
		return
	}

	if user.Password == "" {
		errors.Message = "Password is missing."
		utils.RespondWithError(w, http.StatusBadRequest, errors)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatalln(err)
	}
	user.Password = string(hash)
	statement := "insert into users (email, password) values($1, $2) RETURNING id;"

	err = db.QueryRow(statement, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		errors.Message = "Server error"
		utils.RespondWithError(w, http.StatusInternalServerError, errors)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	utils.ResponseJSON(w, user)
}

func generateToken(user models.User) (string, error) {
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

func login(w http.ResponseWriter, r *http.Request) {

	var user models.User
	var jwt models.JWT
	var errors models.Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		errors.Message = "Email is missing."
		utils.RespondWithError(w, http.StatusBadRequest, errors)
		return
	}

	if user.Password == "" {
		errors.Message = "Password is missing."
		utils.RespondWithError(w, http.StatusBadRequest, errors)
		return
	}

	password := user.Password
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			errors.Message = "The user does not exist"
			utils.RespondWithError(w, http.StatusBadRequest, errors)
			return
		}
		log.Fatalln(err)
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		errors.Message = "Invalid Password"
		utils.RespondWithError(w, http.StatusUnauthorized, errors)
		return
	}

	token, err := generateToken(user)
	if err != nil {
		log.Fatalln(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	utils.ResponseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked...")

}

// TokenVerifyMiddleWare protected handle
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(os.Getenv("SECRET")), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid Token."
			utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}
