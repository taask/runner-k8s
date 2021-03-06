package model

import (
	"math/rand"
	"time"
)

// UUIDLength and others are consts for UUIDs
const (
	UUIDLength        = 26
	lowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	uppercaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// NewTaskUUID returns a new task UUID
func NewTaskUUID() string {
	return lowercaseUUID()
}

// NewResultToken retuens a result token
func NewResultToken() string {
	return lowercaseUUID()[:12]
}

// NewRunnerUUID returns a new task UUID
func NewRunnerUUID() string {
	return uppercaseUUID()
}

func uppercaseUUID() string {
	uuid := ""

	for i := 0; i < UUIDLength; i++ {
		index := rand.Intn(len(uppercaseAlphabet))

		uuid += string(uppercaseAlphabet[index])
	}

	return uuid
}

func lowercaseUUID() string {
	uuid := ""

	for i := 0; i < UUIDLength; i++ {
		index := rand.Intn(len(lowercaseAlphabet))

		uuid += string(lowercaseAlphabet[index])
	}

	return uuid
}
