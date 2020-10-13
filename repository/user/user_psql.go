package userrepository

import (
	"database/sql"
	"log"

	"github.com/mrinjamul/go-jwt-rest-api/models"
)

// UserRepository struct
type UserRepository struct {
}

func logFatal(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

// Signup will register
func (u UserRepository) Signup(db *sql.DB, user models.User) models.User {
	statement := "insert into users (email, password) values($1, $2) RETURNING id;"

	err := db.QueryRow(statement, user.Email, user.Password).Scan(&user.ID)
	logFatal(err)
	user.Password = ""
	return user
}

// Login will login
func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		return user, err
	}
	return user, nil
}
