package sqliteStorage

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

func CreateSqlite(name string) error {
	DBName := fmt.Sprintf("./data/%s.db", name)
	os.Create(DBName)

	db, err := sql.Open("sqlite3", DBName)
	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec("CREATE TABLE `passwords` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `password` VARCHAR(255) NOT NULL)")
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE `users` (`password` VARCHAR(255) NOT NULL)")
	db.

	return nil
}
