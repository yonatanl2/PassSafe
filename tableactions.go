// tableactions project tableactions.go
package tableactions

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"passcypher"

	"github.com/elithrar/simple-scrypt"
	_ "github.com/lib/pq"
)

type credentials struct {
	Platform string
	User     string
	Password string
}

//const dbInfo = "host=localhost port=5432 user=postgres dbname=PassCypher sslmode=disable"
var dbInfo = map[int]string{
	0: "sqlite3",
	1: "./data/passsafe.db",
}

func SetDB(dbArchitecture string, host string) {
	dbInfo[0] = dbArchitecture
	dbInfo[1] = host
}

func InsertValue(value string) error {
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return err
	}
	rows, err := db.Query("select id from passwords")
	if err != nil {
		return err
	}
	defer rows.Close()
	var id int
	for rows.Next() {
		err := rows.Scan(&id)
		if err != nil {
			return err
		}
	}
	id++
	inserQuery := fmt.Sprintf(`INSERT INTO passwords(id, password) 
								VALUES(%d, '%s')`, id, value)
	_, err = db.Exec(inserQuery)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func binaryToStruct(bits []byte) (*credentials, error) {

	var decypherBits credentials
	//byteValue := flag/
	err := json.Unmarshal(bits, &decypherBits)
	if err != nil {
		return nil, err
	}

	return &decypherBits, nil
}

func DecypherTable(password []byte) ([]credentials, error) {
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return nil, err
	}
	rows, err := db.Query("select count(*) from passwords")
	if err != nil {
		return nil, err
	}
	count := 0
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&count)
		if err != nil {
			return nil, err
		}
	}
	credarray := make([]credentials, count)
	rows, err = db.Query("select password from passwords")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var pass string
	i := 0
	for rows.Next() {
		err := rows.Scan(&pass)
		if err != nil {
			return nil, err
		}
		decodedValueBytes, err := passcypher.GenerateDecryptedPEM(&pass, password)
		if err != nil {
			return nil, err
		}
		decodedToStruct, err := binaryToStruct(*decodedValueBytes)
		if err != nil {
			return nil, err
		}
		fmt.Println(decodedToStruct)
		credarray[i] = *decodedToStruct
		i++
	}
	return credarray, nil
}

func isNewUser(password *string) (bool, error) {
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return false, err
	}
	rows, err := db.Query("select password from users limit 1")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var pass string

	for rows.Next() {
		err := rows.Scan(&pass)
		if err != nil {
			return false, err
		}
	}
	if pass != "" {
		return false, nil
	} else {
		err = createUser(password)
		if err != nil {
			return false, err
		}
		return true, nil
	}
}

func createUser(password *string) error {
	hashedPassword, err := scrypt.GenerateFromPassword([]byte(*password), scrypt.DefaultParams)
	if err != nil {
		panic(err)
	}
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return err
	}
	inserQuery := fmt.Sprintf(`INSERT INTO users (password) 
								VALUES('%s')`, hashedPassword)
	_, err = db.Exec(inserQuery)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func Validate(password string) error {
	newUser, err := isNewUser(&password)
	if err != nil {
		return err
	}
	if !newUser {
		db, err := sql.Open(dbInfo[0], dbInfo[1])
		defer db.Close()
		if err != nil {
			return err
		}
		rows, err := db.Query("select password from users limit 1")
		if err != nil {
			return err
		}
		defer rows.Close()
		var hash string
		for rows.Next() {
			err := rows.Scan(&hash)
			if err != nil {
				return err
			}
		}
		err = scrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			fmt.Println("Unmatching passwords.")
			panic(err)
		}
		return nil
	} else {
		return nil
	}

}
