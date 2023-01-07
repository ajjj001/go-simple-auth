package helpers

import (
	"encoding/json"
	"net/http"

	"github.com/ajjj001/go-simple-auth/responses"
)

func RenderJSON(w http.ResponseWriter, data interface{}, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err != nil {
		json.NewEncoder(w).Encode(responses.Error{Error: err.Error()})
		return
	}

	json.NewEncoder(w).Encode(data)
}
