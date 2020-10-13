package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
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

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	err := http.ListenAndServe(":8000", router)

	if err != nil {
		log.Fatal(err)
	}
	log.Println("Listen on port 8000...")
}

func signup(w http.ResponseWriter, r *http.Request) {
	fmt.Println("signup invoked...")
}

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("login invoked...")

}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked...")

}

// TokenVerifyMiddleWare protected handle
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenVerifyMiddleWare invoked...")
	return nil
}
