package models

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Replication struct {
	UniqID       string    `gorm:"PRIMARY_KEY"`
	CreationDate time.Time `gorm:"autoCreateTime"`
	Instance     string
	Action       string
	Data         string
}

type ReplicationData map[string]string

func (r *Replication) BeforeCreate(tx *gorm.DB) (err error) {
	r.UniqID = uuid.New().String()
	return
}

// Delete removes the access from the provided database
func (r *Replication) Delete(db *gorm.DB) (err error) {
	// We delete our access
	return db.Delete(r).Error
}

// Save saves the replication entry in the provided database
func (r *Replication) Save(db *gorm.DB) (err error) {
	// We insert or update our access
	return db.Save(r).Error
}

func GetNextReplicationEntryToPush(db *gorm.DB) (entry Replication, err error) {

	err = db.Limit(1).Order("creation_date ASC").Find(&entry).Error

	return
}

func NewReplicationEntry(action string, data ReplicationData) (repl *Replication, err error) {

	hostname, err := helpers.GetHostname()
	if err != nil {
		return
	}

	encryptedPayload, err := EncryptReplicationDataForTransport(data)
	if err != nil {
		return
	}

	repl = &Replication{
		Instance: hostname,
		Action:   action,
		Data:     encryptedPayload,
	}

	return
}

func EncryptReplicationDataForTransport(data ReplicationData) (encrypted string, err error) {

	// Let's start by json encode our type
	dataStr, err := json.Marshal(data)
	if err != nil {
		return
	}

	cipherKey := config.GetEncryptionKey()

	// The key is used directly as the AES key below, so it must be a valid AES
	// length. This shares config's source of truth with the daemon startup guard
	// (config.ValidateSecretsEncryption), which is why the previous hand-written
	// check here was wrong in both directions: it accepted 8 bytes (which
	// aes.NewCipher rejects anyway) and rejected 24 bytes (valid AES-192).
	if !config.EncryptionKeyHasValidLength(cipherKey) {
		err = fmt.Errorf("cipher key must be 16, 24 or 32 bytes, got %d", len(cipherKey))
		return
	}

	var cipherText []byte

	if cipherKey != "" {

		var c cipher.Block
		var gcm cipher.AEAD
		var nonce []byte

		// Then, let's AES encrypt the json data
		c, err = aes.NewCipher([]byte(cipherKey))
		if err != nil {
			return
		}
		gcm, err = cipher.NewGCM(c)
		if err != nil {
			return
		}
		nonce = make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return
		}

		cipherText = gcm.Seal(nonce, nonce, dataStr, nil)
	} else {
		cipherText = dataStr
	}

	encrypted = base64.StdEncoding.EncodeToString(cipherText)

	return
}

func DecryptReplicationData(encryptedPayload string) (data ReplicationData, err error) {

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPayload)
	if err != nil {
		return
	}

	cipherKey := config.GetEncryptionKey()

	var plaintext []byte

	if cipherKey != "" {

		var c cipher.Block
		var gcm cipher.AEAD
		var nonceSize int

		c, err = aes.NewCipher([]byte(cipherKey))
		if err != nil {
			return
		}

		gcm, err = cipher.NewGCM(c)
		if err != nil {
			return
		}

		nonceSize = gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			return
		}

		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return
		}

	} else {
		plaintext = ciphertext
	}

	err = json.Unmarshal(plaintext, &data)

	return
}
