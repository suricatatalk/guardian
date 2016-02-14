package auth

import (
	"log"
	"testing"
	"time"
)

func TestPasswordHashing(t *testing.T) {
	secret := "secret"
	output, err := encryptPassword(secret)
	if err != nil {
		t.Errorf("Bcrypt failed %s", err)
	}

	if !comparePasswordHash(output, secret) {
		t.Error("Password not equal")
	}

}

func TestComplete(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	authProvider := NewAuthProvider(mongo)

	user := User{
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Add(72 * time.Hour).Unix(),
		LastAccess: time.Now().Unix(),
	}

	log.Println(user)

	err := authProvider.SignUp(user)
	if err != nil {
		t.Error(err)
		t.Error("Couldnt sign up")
		return
	}

	user, signInErr := authProvider.SignIn(user.Email, "ABCDEF")
	if signInErr != nil {
		t.Error(signInErr)
		return
	}
	log.Println(user)

}
