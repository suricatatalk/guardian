package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	ErrUserAlreadyExist = errors.New("User already exist")
)

//User structure
//to hold user data
type User struct {
	Id         bson.ObjectId `bson:"_id"`
	UserID     string
	Email      string
	Password   string
	Expiration int64
	LastAccess int64
	Activated  bool
}

func (user User) Equals(other *User) bool {
	match := user.Email == other.Email
	match = match && user.Password == other.Password
	match = match && user.Expiration == other.Expiration
	match = match && user.LastAccess == other.LastAccess
	return match
}

func NewInactiveUser() User {
	user := User{
		Activated: false,
	}
	return user
}

//Creates the user from given map.
//Generally to use with JWT token decoding
func NewUser(m map[string]interface{}) (*User, error) {
	//TODO rewrite to non-ugly
	user := &User{}
	mId, ok := m["Id"]
	if ok {
		user.Id = bson.ObjectId(mId.(string))
	}
	email, emailok := m["Email"]
	if emailok {
		user.Email = email.(string)
	}
	pass, passOk := m["Password"]
	if passOk {
		user.Password = pass.(string)
	}
	exp, expOk := m["Expiration"]
	if expOk {

		user.Expiration = int64(exp.(float64))
	}
	access, accessOk := m["LastAccess"]
	if accessOk {

		user.LastAccess = int64(access.(float64))
	}
	return user, nil
}

type Token struct {
	Id         bson.ObjectId `bson:"_id"`
	Email      string
	RefToken   string
	JwtToken   string
	Expiration int64
}

func NewToken(user User, jwtToken string) Token {
	token := Token{}
	token.JwtToken = jwtToken
	token.Email = user.Email
	token.RefToken = uuid.NewV4().String()
	token.Expiration = time.Now().Add(time.Hour * 72).Unix()
	return token
}

type Activity struct {
	ID         bson.ObjectId `bson:"_id"`
	Type       string
	Token      string
	User       string
	Time       int64
	Expiration int64
	Used       int64 `bson:",omitempty"`
}

type UserStorage interface {
	InsertUser(user User) error
	UpdateUser(user User) error
	DeleteUser(userId string) error
	ActivateUser(activationToken string) error
	UserByEmail(email string) (User, error)
	UserByID(hexID string) (User, error)
}

type ActivityStorage interface {
	InsertActivity(activity *Activity) error
	UpdateActivity(activity *Activity) error
	GetActivityByToken(token string) (Activity, error)
}

type DataStorage interface {
	UserStorage
	ActivityStorage
	OpenSession() error
	CloseSession()
}

type MgoDataStorage struct {
	ConnectionString string
	Database         string
	users            string
	tokens           string
	activities       string
	mgoSession       *mgo.Session
	mgoDB            *mgo.Database
	mgoUsers         *mgo.Collection
	mgoTokens        *mgo.Collection
	mgoActivities    *mgo.Collection
}

func NewMgoStorage() *MgoDataStorage {
	return &MgoDataStorage{
		ConnectionString: "localhost:27017",
		Database:         "surikata_auth",
		users:            "users",
		tokens:           "tokens",
		activities:       "activities",
	}

}

func (a *MgoDataStorage) OpenSession() error {
	var err error
	a.mgoSession, err = mgo.Dial(a.ConnectionString)
	if err != nil {
		return err
	}
	a.mgoDB = a.mgoSession.DB(a.Database)
	a.mgoUsers = a.mgoDB.C(a.users)
	a.mgoTokens = a.mgoDB.C(a.tokens)
	a.mgoActivities = a.mgoDB.C(a.activities)

	a.mgoUsers.EnsureIndex(mgo.Index{
		Key:        []string{"email"},
		Unique:     true,
		Background: true,
	})
	return nil
}

func (a *MgoDataStorage) CloseSession() {
	a.mgoSession.Close()
}

func (a *MgoDataStorage) InsertUser(user User) error {
	user.Id = bson.NewObjectId()
	err := a.mgoUsers.Insert(&user)
	if err != nil && strings.Contains(err.Error(), "E11000 duplicate key") {
		return ErrUserAlreadyExist
	}
	return err
}

func (a *MgoDataStorage) UpdateUser(user User) error {
	return a.mgoUsers.Update(bson.M{"email": user.Email}, bson.M{"$set": bson.M{
		"password":   user.Password,
		"userid":     user.UserID,
		"expiration": user.Expiration,
		"lastaccess": user.LastAccess,
		"activated":  user.Activated,
	}})
}

func (a *MgoDataStorage) DeleteUser(email string) error {
	return a.mgoUsers.Remove(bson.M{"email": email})
}

func (a *MgoDataStorage) ActivateUser(activationToken string) error {
	return a.mgoUsers.Update(bson.M{"activationtoken": activationToken},
		bson.M{"$set": bson.M{"activated": true, "activationtoken": ""}})
}

func (a *MgoDataStorage) UserByEmail(email string) (User, error) {
	user := User{}
	err := a.mgoUsers.Find(bson.M{"email": email}).One(&user)
	if user.Email != email {
		return user, err
	}
	return user, err
}

func (a *MgoDataStorage) UserByID(hexID string) (User, error) {
	user := User{}
	err := a.mgoUsers.FindId(bson.ObjectIdHex(hexID)).One(&user)
	if user.Id.Hex() != hexID {
		return user, err
	}
	return user, err
}

func (a *MgoDataStorage) InsertActivity(activity *Activity) error {
	activity.ID = bson.NewObjectId()
	return a.mgoActivities.Insert(&activity)
}

func (a *MgoDataStorage) UpdateActivity(activity *Activity) error {
	return a.mgoActivities.UpdateId(activity.ID, &activity)
}

func (a *MgoDataStorage) GetActivityByToken(tkn string) (Activity, error) {
	activity := Activity{}
	err := a.mgoActivities.Find(bson.M{"token": tkn}).One(&activity)
	return activity, err
}
