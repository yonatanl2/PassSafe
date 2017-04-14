package mysqlStorage

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func CreateMysql(name string) error {

	db, err := sql.Open("mysql", "localhost:3306")
	if err != nil {
		return err
	}

	defer db.Close()

	_, err = db.Exec("CREATE DATABASE " + name)
	if err != nil {
		return err
	}

	_, err = db.Exec("USE " + name)
	if err != nil {
		return err
	}

	_, err = db.Exec("CREATE TABLE `passwords` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `password` VARCHAR(255) NOT NULL)")
	if err != nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE `users` (`password` VARCHAR(255) NOT NULL)")
	if err != nil {
		return err
	}
	return nil

}
