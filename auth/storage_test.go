package auth

import (
	"log"
	"testing"
	"time"

	"gopkg.in/mgo.v2/bson"
)

func cleanUp(store *MgoDataStorage) {
	store.mgoDB.DropDatabase()
	store.CloseSession()
}

func createMgoStorage() *MgoDataStorage {
	mongo := NewMgoStorage()
	mongo.Database = "surikata_test"
	mongo.OpenSession()
	return mongo
}

func TestInsertUser(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}

}

func TestInsertMultiple(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}

	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	err = mongo.InsertUser(user)
	if err == nil {
		t.Error("Unique index not working")
	}

}

func TestUserByEmail(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}
	userByEmail, userByMailErr := mongo.UserByEmail(user.Email)
	if userByMailErr != nil {
		log.Println(userByMailErr)
		t.Error("Error selecting user")
		return
	}

	match := user.Equals(&userByEmail)
	if !match {
		t.Error("Users not match")
	}
}

func TestDeleteUser(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}
	mongo.DeleteUser(user.Email)
	count, err = mongo.mgoUsers.Count()
	if err == nil && count != 0 {
		t.Error("User not deleted")
	}
}

func TestActivateUser(t *testing.T) {
	mongo := createMgoStorage()
	defer cleanUp(mongo)
	user := User{
		Id:         bson.NewObjectId(),
		Email:      "sohlich@example.com",
		Password:   "ABCDEF",
		Expiration: time.Now().Unix(),
		LastAccess: time.Now().Unix(),
		Activated:  false,
	}
	err := mongo.InsertUser(user)
	if err != nil {
		t.Error(err)
	}
	count, err := mongo.mgoUsers.Count()
	if err == nil && count != 1 {
		t.Error("User not inserted")
	}
	user.Activated = true
	err = mongo.UpdateUser(user)
	if err != nil {
		t.Error(err)
	}
	dbUser, _ := mongo.UserByEmail(user.Email)
	if !dbUser.Activated {
		t.Error("User not activated")
	}
}
