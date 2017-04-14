// passcypher project passcypher.go
package passcypher

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
)

type Credentials struct {
	Platform string
	User     string
	Password string
}

func encryptedPEM(content []byte, pwd []byte) ([]byte, error) {
	block := &pem.Block{
		Type:  "ENCRYPTED KEY",
		Bytes: content,
	}
	if string(pwd) != "" {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
	}

	return pem.EncodeToMemory(block), nil

}

func decryptPEM(pemBytes []byte, password []byte) ([]byte, error) {

	p, _ := pem.Decode(pemBytes)

	decrypted, err := x509.DecryptPEMBlock(p, password)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func bytesToBase64(cypherBytes []byte) *string {
	newString := base64.StdEncoding.EncodeToString([]byte(cypherBytes))
	return &newString
}

func base64ToBytes(baseValue *string) ([]byte, error) {
	baseValueString := *baseValue
	newBytes, err := base64.StdEncoding.DecodeString(baseValueString)
	if err != nil {
		return nil, err
	}
	newBytes = []byte(newBytes)

	return newBytes, nil
}

func GenerateEncryptedPEM(inputCredentials Credentials, password []byte) (*string, error) {

	b, err := json.Marshal(inputCredentials)
	if err != nil {
		return nil, err
	}

	pemBlock, err := encryptedPEM(b, password)
	if err != nil {
		return nil, err
	}

	encodedValue := bytesToBase64(pemBlock)
	return encodedValue, nil

}

func GenerateDecryptedPEM(base64Value *string, password []byte) (*[]byte, error) {
	decodedValue, err := base64ToBytes(base64Value)
	if err != nil {
		return nil, err
	}

	decryptedBytes, err := decryptPEM(decodedValue, password)
	if err != nil {
		return nil, err
	}
	return &decryptedBytes, nil
}
