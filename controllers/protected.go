package controllers

import (
	"fmt"
	"net/http"
)

// ProtectedEndpoint return protected HandlerFunc
func (c Controller) ProtectedEndpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("protectedEndpoint invoked...")
	}
}
