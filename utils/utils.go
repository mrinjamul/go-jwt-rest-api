package utils

import (
	"encoding/json"
	"net/http"

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
