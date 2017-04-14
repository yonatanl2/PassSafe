package main

import (
	"bufio"
	"crypto/sha512"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"passcypher"
	"safeui"
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
		secret, _ = safeui.GeneratePass(12)
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
			err := safeui.ReadPrefrences(&mapField, prefrenceFile)
			if err != nil {
				fck(err)
			}
			tableactions.SetDB(mapField[0], mapField[1])
			scanner, sha512PassHash := login()
			create(scanner, &sha512PassHash)

		} else if strings.ToLower(os.Args[1]) == "read" {
			var mapField map[int]string
			err := safeui.ReadPrefrences(&mapField, prefrenceFile)
			if err != nil {
				fck(err)
			}
			tableactions.SetDB(mapField[0], mapField[1])

			_, sha512PassHash := login()
			read(&sha512PassHash)

		} else if strings.ToLower(os.Args[1]) == "sqlite" {
			tableactions.SetSQLite()
			login()
			fmt.Println("Set SQLite DB")
		} else if strings.ToLower(os.Args[1]) == "mysql" {
			tableactions.SetMySQL()
			login()
			fmt.Println("Set MySQL DB")

		} else if strings.ToLower(os.Args[1]) == "psql" {
			tableactions.SetPLSQL()
			login()
			fmt.Println("Set PSQL DB")
		} else {
			panic("Invalid Arguement!")
		}
	} else {
		safeui.LoadUI(prefrenceFile)
	}
}

func fck(err error) error {
	if err != nil {
		log.Fatal(err)
		return err
	}
	return nil
}
