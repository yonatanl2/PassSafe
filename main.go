package main

import (
	"bufio"
<<<<<<< HEAD
	"crypto/sha512"
	"fmt"
=======
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/gob"
	"fmt"
	"io"
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
	"io/ioutil"
	"log"
	"mysqlStorage"
	"os"
	"passcypher"
<<<<<<< HEAD
	"safeui"
=======
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
	"sqliteStorage"
	"strings"
	"tableactions"

	"github.com/howeyc/gopass"
)

const dataDirectory = "./data/"
const prefrenceFile = "./data/prefrences"

func create(scanner *bufio.Scanner, hash *[]byte) {
	fmt.Println("Please enter the Platform:")
	scanner.Scan()
	platform := scanner.Text()
	fmt.Println("Please enter the Username:")
	scanner.Scan()
	id := scanner.Text()
	fmt.Println("Please enter the Password:")
	scanner.Scan()
	secret := scanner.Text()
	if secret == "" {
<<<<<<< HEAD
		secret, _ = safeui.GeneratePass(12)
=======
		secret, _ = generatePass(12)
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
	}

	t := passcypher.Credentials{
		Platform: platform,
		User:     id,
		Password: secret,
	}

	encodedValue, _ := passcypher.GenerateEncryptedPEM(t, *hash)
	tableactions.InsertValue(*encodedValue)
}

func read(hash *[]byte) {
	arr, err := tableactions.DecypherTable(*hash)
	fck(err)
	for index, obj := range arr {
		fmt.Printf("%d. Platform: %s | Username: %s | Password: %s", index+1, obj.Platform, obj.User, obj.Password)
	}
}

<<<<<<< HEAD
=======
func generatePass(charLen int) (string, error) {
	chars := []byte(`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]~`)

	i := 0
	pass := make([]byte, charLen)
	placeHolder := make([]byte, charLen+(charLen/4))
	clen := byte(len(chars))
	maxrb := byte(256 - (256 % len(chars)))
	for {
		_, err := io.ReadFull(rand.Reader, placeHolder)
		if err != nil {
			return "", err
		}
		for _, c := range placeHolder {
			if c >= maxrb {
				continue
			}
			pass[i] = chars[c%clen]
			i++
			if i == charLen {
				return string(pass), nil
			}
		}
	}
}

>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
func login() (*bufio.Scanner, []byte) {

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Login..")
	fmt.Println("User Name")
	scanner.Scan()
	userName := scanner.Text()
	fmt.Println("Password")

	password, err := gopass.GetPasswdMasked()
	fck(err)
	creds := userName + string(password)
	err = tableactions.Validate(creds)
	fck(err)

	sha512Pass := sha512.New()
	sha512Pass.Write([]byte(creds))
	return scanner, sha512Pass.Sum(nil)
}

<<<<<<< HEAD
=======
func getMapBytes(mapText map[int]string) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(mapText)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func byteToMap(fileBytes []byte, decodedMap *map[int]string) error {
	buf := bytes.NewBuffer(fileBytes)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&decodedMap)
	if err != nil {
		return nil
	}
	return nil
}

func readPrefrences(mapField *map[int]string) error {
	bytes, err := ioutil.ReadFile(prefrenceFile)
	if err != nil {
		return err
	}
	err = byteToMap(bytes, mapField)
	if err != nil {
		return err
	}
	return nil
}

>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
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
<<<<<<< HEAD
	fileBytes, err := safeui.GetMapBytes(prefrences)
=======
	fileBytes, err := getMapBytes(prefrences)
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
	if err != nil {
		return err
	}
	_, err = file.Write(fileBytes)
	if err != nil {
		return err
	}
	return nil
}

func main() {

	_, err := ioutil.ReadDir(dataDirectory)
	if err != nil {
		os.MkdirAll(dataDirectory, 0755)
	}

	_, err = ioutil.ReadFile(prefrenceFile)
	if err != nil {
		os.Create(prefrenceFile)
	}

	if len(os.Args) > 1 {
		if strings.ToLower(os.Args[1]) == "create" {
			var mapField map[int]string
<<<<<<< HEAD
			err := safeui.ReadPrefrences(&mapField, prefrenceFile)
=======
			err := readPrefrences(&mapField)
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
			if err != nil {
				fck(err)
			}
			tableactions.SetDB(mapField[0], mapField[1])
			scanner, sha512PassHash := login()
			create(scanner, &sha512PassHash)

		} else if strings.ToLower(os.Args[1]) == "read" {
			var mapField map[int]string
<<<<<<< HEAD
			err := safeui.ReadPrefrences(&mapField, prefrenceFile)
=======
			err := readPrefrences(&mapField)
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
			if err != nil {
				fck(err)
			}
			tableactions.SetDB(mapField[0], mapField[1])

			_, sha512PassHash := login()
			read(&sha512PassHash)

		} else if strings.ToLower(os.Args[1]) == "sqlite" {
			_, err = ioutil.ReadFile("./data/passsafe.db")
			if err != nil {
				err = sqliteStorage.CreateSqlite("passsafe")
				if err != nil {
					fck(err)
				}
			}

			err := writeToFile(map[int]string{0: "sqlite3", 1: "./data/passsafe.db"})
			if err != nil {
				fck(err)
			}

			tableactions.SetDB("sqlite3", "./data/passsafe.db")
			login()
			fmt.Println("Set SQLite DB")
		} else if strings.ToLower(os.Args[1]) == "mysql" {
			err := mysqlStorage.CreateMysql("passsafe")
			if err != nil {
				fck(err)
			}
			tableactions.SetDB("mysql", "passsafe")
			login()
		} else if strings.ToLower(os.Args[1]) == "psql" {
			err := writeToFile(map[int]string{0: "postgres", 1: "host=localhost port=5432 user=postgres dbname=PassCypher sslmode=disable"})
			if err != nil {
				fck(err)
			}
			fmt.Println("Set PSQL DB")
		} else {
			panic("Invalid Arguement!")
		}
	} else {
<<<<<<< HEAD
		safeui.LoadUI(prefrenceFile)
=======
		panic("Missing Arguements!")
>>>>>>> 29617df7291980c280282e9db021dbb4165f7342
	}
}

func fck(err error) error {
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}
