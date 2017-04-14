// safeui project safeui.go
package safeui

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/gob"
	"io"
	"io/ioutil"
	"log"
	"passcypher"
	"tableactions"

	"github.com/andlabs/ui"
)

func ReadPrefrences(mapField *map[int]string, prefrenceFile string) error {
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

func uiLogin(userName string, password string) ([]byte, error) {

	creds := userName + password
	err := tableactions.Validate(creds)
	if err != nil {
		return nil, err
	}

	sha512Pass := sha512.New()
	sha512Pass.Write([]byte(creds))
	return sha512Pass.Sum(nil), nil
}

func uiCreate(id string, secret string, platform string, hash *[]byte) bool {

	if secret == "" {
		return false
	}

	t := passcypher.Credentials{
		Platform: platform,
		User:     id,
		Password: secret,
	}

	encodedValue, _ := passcypher.GenerateEncryptedPEM(t, *hash)
	tableactions.InsertValue(*encodedValue)
	return true
}

func byteToMap(fileBytes []byte, decodedMap *map[int]string) error {
	buf := bytes.NewBuffer(fileBytes)
	dec := gob.NewDecoder(buf)
	err := dec.Decode(&decodedMap)
	if err != nil {
		return err
	}
	return nil
}

func GeneratePass(charLen int) (string, error) {
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

func uiUpdate(index int, platform string, id string, secret string, hash *[]byte) bool {
	if secret == "" {
		return false
	}

	t := passcypher.Credentials{
		Platform: platform,
		User:     id,
		Password: secret,
	}

	encodedValue, _ := passcypher.GenerateEncryptedPEM(t, *hash)
	err := tableactions.Modify(index, encodedValue)
	if err != nil {
		log.Fatal(err)
	}
	return true
}

func readUi(hash *[]byte, box *ui.Box) {
	arr, err := tableactions.DecypherTable(*hash)
	if err != nil {
		panic(err)
	}
	for index, obj := range arr {
		line := ui.NewHorizontalBox()
		separator1 := ui.NewHorizontalSeparator()
		platformLabel := ui.NewLabel(obj.Platform)
		separator2 := ui.NewHorizontalSeparator()
		userLabel := ui.NewLabel(obj.User)
		separator3 := ui.NewHorizontalSeparator()
		secretLabel := ui.NewEntry()
		secretLabel.SetText(obj.Password)
		separator4 := ui.NewHorizontalSeparator()
		saveButton := ui.NewButton("SAVE")
		saveButton.OnClicked(func(*ui.Button) {
			result := uiUpdate(index+1, obj.Platform, obj.User, secretLabel.Text(), hash)
			if !result {
				panic(result)
			}
		})
		deleteButton := ui.NewButton("DELETE")
		deleteButton.OnClicked(func(*ui.Button) {
			window := ui.NewWindow("DELETE", 150, 50, false)
			window.SetMargined(true)
			selectionVertical := ui.NewVerticalBox()
			messageLabel := ui.NewLabel("The following row is about to be deleted. \nPlease confirm.\n")
			deleteLabel := ui.NewLabel("Platform: " + obj.Platform + "\nUser: " + obj.User + "\nPassword: " + obj.Password + "\n")

			selectionVertical.Append(messageLabel, false)
			selectionVertical.Append(deleteLabel, false)

			selectionHorizontal := ui.NewHorizontalBox()
			yesButton := ui.NewButton("YES")
			noButton := ui.NewButton("NO")
			selectionHorizontal.Append(yesButton, true)
			selectionHorizontal.Append(noButton, true)
			selectionHorizontal.SetPadded(true)

			selectionVertical.Append(selectionHorizontal, true)

			yesButton.OnClicked(func(*ui.Button) {
				tableactions.Delete(index + 1)
				line.Hide()
				window.Hide()
				window.Destroy()
			})
			noButton.OnClicked(func(*ui.Button) {
				window.Hide()
				window.Destroy()
			})

			window.OnClosing(func(*ui.Window) bool {
				window.Hide()
				return true
			})
			window.SetChild(selectionVertical)
			window.Show()

		})
		line.Append(separator1, false)
		line.Append(platformLabel, true)
		line.Append(separator2, false)
		line.Append(userLabel, true)
		line.Append(separator3, false)
		line.Append(secretLabel, true)
		line.Append(separator4, false)
		line.Append(saveButton, false)
		line.Append(deleteButton, false)

		line.SetPadded(true)
		box.Append(line, false)

	}
}

func LoadUI(preferenceFile string) {
	err := ui.Main(func() {
		name := ui.NewEntry()
		password := ui.NewEntry()
		var typedPass string
		password.OnChanged(func(*ui.Entry) {
			if len(typedPass) > len(password.Text()) {
				if len(typedPass) != 0 {
					typedPass = typedPass[0:len(password.Text())]
				}
			} else {
				typedPass += string(password.Text()[len(password.Text())-1])
			}
			var tempPass string
			for i := 0; i < len(typedPass); i++ {
				tempPass += "*"
			}
			password.SetText(tempPass)
		})
		button := ui.NewButton("Login")
		combo := ui.NewCombobox()
		combo.Append("SQLite")
		combo.Append("PostgreSQL")
		combo.Append("MySQL")
		userLabel := ui.NewLabel("User Name")
		passLabel := ui.NewLabel("Password")
		box := ui.NewVerticalBox()
		box.Append(userLabel, false)
		box.Append(name, false)
		box.Append(passLabel, false)
		box.Append(password, false)
		box.Append(combo, false)
		box.Append(button, false)

		var mapField map[int]string
		err := ReadPrefrences(&mapField, preferenceFile)
		if err != nil {
			combo.SetSelected(0)
		}
		switch mapField[0] {
		case "sqlite3":
			combo.SetSelected(0)
		case "postgres":
			combo.SetSelected(1)
		case "mysql":
			combo.SetSelected(2)
		default:
			combo.SetSelected(0)

		}
		window := ui.NewWindow("Pass Safe", 900, 900, false)
		loginWindow := ui.NewWindow("Login", 300, 150, false)
		loginWindow.SetMargined(true)
		loginWindow.SetChild(box)
		button.OnClicked(func(*ui.Button) {

			err := ReadPrefrences(&mapField, preferenceFile)
			if err != nil {
				switch combo.Selected() {
				case 0:
					tableactions.SetSQLite()
				case 1:
					tableactions.SetPLSQL()
				case 2:
					tableactions.SetMySQL()
				}
			}

			hash, err := uiLogin(name.Text(), typedPass)
			successPopUp := ui.NewWindow("Message", 150, 50, false)
			successButton := ui.NewButton("Close")
			verticalView := ui.NewVerticalBox()
			if err != nil {
				succesLabel := ui.NewLabel("Login Failed")
				verticalView.Append(succesLabel, false)
				verticalView.Append(successButton, false)
				successPopUp.SetChild(verticalView)
				successPopUp.SetMargined(true)
				successPopUp.Show()
				successButton.OnClicked(func(*ui.Button) {
					successPopUp.Hide()
					successPopUp.Destroy()
				})
				successPopUp.OnClosing(func(*ui.Window) bool {
					successPopUp.Hide()
					return true
				})
			} else {

				switch combo.Selected() {
				case 0:
					tableactions.SetSQLite()
				case 1:
					tableactions.SetPLSQL()
				case 2:
					tableactions.SetMySQL()
				}
				succesLabel := ui.NewLabel("Login Successful")
				verticalView.Append(succesLabel, false)
				verticalView.Append(successButton, false)
				successPopUp.SetChild(verticalView)
				successPopUp.SetMargined(true)
				successPopUp.Show()
				successButton.OnClicked(func(*ui.Button) {
					successPopUp.Hide()
					successPopUp.Destroy()
					loginWindow.Hide()
					loginWindow.Destroy()

					mainVerticalView := ui.NewVerticalBox()
					platformLabel := ui.NewLabel("Platform:")
					idLabel := ui.NewLabel("Platform ID:")
					secretLabel := ui.NewLabel("Secret:")
					platformEntry := ui.NewEntry()
					idEntry := ui.NewEntry()
					secretEntry := ui.NewEntry()
					mainVerticalView.Append(platformLabel, false)
					mainVerticalView.Append(platformEntry, false)
					mainVerticalView.Append(idLabel, false)
					mainVerticalView.Append(idEntry, false)
					mainVerticalView.Append(secretLabel, false)
					mainVerticalView.Append(secretEntry, false)

					buttonHorizontalBox := ui.NewHorizontalBox()

					submitButton := ui.NewButton("Submit")
					submitButton.OnClicked(func(*ui.Button) {
						index, err := tableactions.GetLastID()
						if err != nil {
							panic(err)
						}

						success := uiCreate(idEntry.Text(), secretEntry.Text(), platformEntry.Text(), &hash)

						line := ui.NewHorizontalBox()
						platformLabel := ui.NewLabel(platformEntry.Text())
						userLabel := ui.NewLabel(idEntry.Text())
						secretLabel := ui.NewEntry()
						secretLabel.SetText(secretEntry.Text())
						saveButton := ui.NewButton("SAVE")
						saveButton.OnClicked(func(*ui.Button) {

							result := uiUpdate(index, platformLabel.Text(), userLabel.Text(), secretLabel.Text(), &hash)
							if !result {
								panic(result)
							}
						})
						deleteButton := ui.NewButton("DELETE")
						deleteButton.OnClicked(func(*ui.Button) {
							window := ui.NewWindow("DELETE", 150, 50, false)
							window.SetMargined(true)
							selectionVertical := ui.NewVerticalBox()
							messageLabel := ui.NewLabel("The following row is about to be deleted. \nPlease confirm.\n")
							deleteLabel := ui.NewLabel("Platform: " + platformLabel.Text() + "\nUser: " + userLabel.Text() + "\nPassword: " + secretLabel.Text() + "\n")

							selectionVertical.Append(messageLabel, false)
							selectionVertical.Append(deleteLabel, false)

							selectionHorizontal := ui.NewHorizontalBox()
							yesButton := ui.NewButton("YES")
							noButton := ui.NewButton("NO")
							selectionHorizontal.Append(yesButton, true)
							selectionHorizontal.Append(noButton, true)
							selectionHorizontal.SetPadded(true)

							selectionVertical.Append(selectionHorizontal, true)

							yesButton.OnClicked(func(*ui.Button) {
								tableactions.Delete(index + 1)
								line.Hide()
								window.Hide()
								window.Destroy()
							})
							noButton.OnClicked(func(*ui.Button) {
								window.Hide()
								window.Destroy()
							})

							window.OnClosing(func(*ui.Window) bool {
								window.Hide()
								return true
							})
							window.SetChild(selectionVertical)
							window.Show()

						})
						line.Append(ui.NewHorizontalSeparator(), false)
						line.Append(platformLabel, true)
						line.Append(ui.NewHorizontalSeparator(), false)
						line.Append(userLabel, true)
						line.Append(ui.NewHorizontalSeparator(), false)
						line.Append(secretLabel, true)
						line.Append(ui.NewHorizontalSeparator(), false)
						line.Append(saveButton, false)
						line.Append(deleteButton, false)

						line.SetPadded(true)
						mainVerticalView.Append(line, false)

						idEntry.SetText("")
						secretEntry.SetText("")
						platformEntry.SetText("")
						if !success {
							panic("NO PASS")
						}
					})
					generateButton := ui.NewButton("Generate Password")
					generateButton.OnClicked(func(*ui.Button) {
						text, err := GeneratePass(12)
						if err != nil {
							panic(err)
						} else {
							secretEntry.SetText(text)
						}
					})

					buttonHorizontalBox.Append(submitButton, true)
					buttonHorizontalBox.Append(ui.NewHorizontalSeparator(), false)
					buttonHorizontalBox.Append(generateButton, true)
					mainVerticalView.Append(buttonHorizontalBox, false)

					mainVerticalView.SetPadded(true)

					gridHorizontal := ui.NewHorizontalBox()
					platformColumn := ui.NewLabel("Platform")
					idColumn := ui.NewLabel("ID")
					secretColummn := ui.NewLabel("Secret")
					gridHorizontal.Append(ui.NewHorizontalSeparator(), false)
					gridHorizontal.Append(platformColumn, true)
					gridHorizontal.Append(ui.NewHorizontalSeparator(), false)
					gridHorizontal.Append(idColumn, true)
					gridHorizontal.Append(ui.NewHorizontalSeparator(), false)
					gridHorizontal.Append(secretColummn, true)
					gridHorizontal.Append(ui.NewHorizontalSeparator(), false)
					gridHorizontal.Append(ui.NewLabel("					"), false)
					gridHorizontal.SetPadded(true)
					verticalSeparator := ui.NewProgressBar()
					mainVerticalView.Append(gridHorizontal, false)
					mainVerticalView.Append(verticalSeparator, false)

					readUi(&hash, mainVerticalView)
					window.SetChild(mainVerticalView)
					window.SetMargined(true)

				})
				successPopUp.OnClosing(func(*ui.Window) bool {
					successPopUp.Hide()
					loginWindow.Hide()
					loginWindow.Destroy()
					return true
				})
			}
		})
		window.OnClosing(func(*ui.Window) bool {
			ui.Quit()
			return true
		})
		loginWindow.OnClosing(func(*ui.Window) bool {
			ui.Quit()
			return true
		})

		window.Show()
		loginWindow.Show()
	})
	if err != nil {
		panic(err)
	}
}
