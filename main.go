package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// User struct
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// JWT struct
type JWT struct {
	Token string `json:"token"`
}

// Error Struct
type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {

	pgURL, err := pq.ParseURL("postgres://nbvhtvrd:2SbF5Be1-ZVrDlYnaDbD0_op1vvuYJhE@ruby.db.elephantsql.com:5432/nbvhtvrd")

	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgURL)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("database connection established")
	}

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")

	err = http.ListenAndServe(":8000", router)

	if err != nil {
		log.Fatal(err)
	}
}

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var errors Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		errors.Message = "Email is missing."
		respondWithError(w, http.StatusBadRequest, errors)
		return
	}

	if user.Password == "" {
		errors.Message = "Password is missing."
		respondWithError(w, http.StatusBadRequest, errors)
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
		respondWithError(w, http.StatusInternalServerError, errors)
		return
	}

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)
}

func generateToken(user User) (string, error) {
	var err error
	secret := "secret"
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

	var user User
	var jwt JWT
	var errors Error

	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		errors.Message = "Email is missing."
		respondWithError(w, http.StatusBadRequest, errors)
		return
	}

	if user.Password == "" {
		errors.Message = "Password is missing."
		respondWithError(w, http.StatusBadRequest, errors)
		return
	}

	password := user.Password
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			errors.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, errors)
			return
		}
		log.Fatalln(err)
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		errors.Message = "Invalid Password"
		respondWithError(w, http.StatusUnauthorized, errors)
		return
	}

	token, err := generateToken(user)
	if err != nil {
		log.Fatalln(err)
	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked...")

}

// TokenVerifyMiddleWare protected handle
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte("secret"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid Token."
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}
