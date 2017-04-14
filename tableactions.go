// tableactions project tableactions.go
package tableactions

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"passcypher"

	"sqliteStorage"

	"io/ioutil"

	"mysqlStorage"

	"os"

	"bytes"
	"encoding/gob"

	"github.com/elithrar/simple-scrypt"
	_ "github.com/lib/pq"
)

type credentials struct {
	Platform string
	User     string
	Password string
}

//const dbInfo = "host=localhost port=5432 user=postgres dbname=PassCypher sslmode=disable"
const prefrenceFile = "./data/prefrences"

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
			return err
		}
		return nil
	} else {
		return nil
	}

}

func Modify(index int, encodedValue *string) error {
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return err
	}
	updateQuery := fmt.Sprintf(`UPDATE passwords SET id=%d,password='%s' WHERE id=%d`, index, *encodedValue, index)
	_, err = db.Exec(updateQuery)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func Delete(index int) error {
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return err
	}
	deleteQuery := fmt.Sprintf(`DELETE FROM passwords WHERE id=%d`, index)
	_, err = db.Exec(deleteQuery)
	if err != nil {
		return err
	} else {
		return nil
	}
}

func GetLastID() (int, error) {
	db, err := sql.Open(dbInfo[0], dbInfo[1])
	defer db.Close()
	if err != nil {
		return 0, err
	}
	rows, err := db.Query(`select max(id) from passwords`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var index int
	for rows.Next() {
		err := rows.Scan(&index)
		if err != nil {
			return 0, err
		}
	}
	return index + 1, err
}

func SetSQLite() error {
	_, err := ioutil.ReadFile("./data/passsafe.db")
	if err != nil {
		err = sqliteStorage.CreateSqlite("passsafe")
		if err != nil {
			return err
		}
	}

	err = writeToFile(map[int]string{0: "sqlite3", 1: "./data/passsafe.db"})
	if err != nil {
		return err
	}

	SetDB("sqlite3", "./data/passsafe.db")
	return nil
}

func SetMySQL() error {
	err := mysqlStorage.CreateMysql("passsafe")
	if err != nil {
		return err
	}
	SetDB("mysql", "passsafe")
	return nil
}

func SetPLSQL() error {
	err := writeToFile(map[int]string{0: "postgres", 1: "host=localhost port=5432 user=postgres dbname=PassCypher sslmode=disable"})
	if err != nil {
		return err
	}
	SetDB("postgres", "host=localhost port=5432 user=postgres dbname=PassCypher sslmode=disable")
	fmt.Println("Set PSQL DB")
	return nil
}

func getMapBytes(mapText map[int]string) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(mapText)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeToFile(prefrences map[int]string) error {
	err := sqliteStorage.CreateSqlite("passsafe")
	if err != nil {
		return err
	}
	file, err := os.Create(prefrenceFile)
	if err != nil {
		return err
	}
	defer file.Close()
	fileBytes, err := getMapBytes(prefrences)
	if err != nil {
		return err
	}
	_, err = file.Write(fileBytes)
	if err != nil {
		return err
	}
	return nil
}
