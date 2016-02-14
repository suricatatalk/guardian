package auth

import (
	"errors"
	"time"

	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	JwtUserKey = "user"
	JwtExpKey  = "exp"
	JwtSecret  = "12345678901234567890123456789012"
)

// Secrutity activtity
const (
	PASSWORD_RESET  = "PASSWORD_RESET"
	USER_ACTIVATION = "USER_ACTIVATION"
)

var (
	ErrUserExpired              = errors.New("User identity expired")
	ErrPasswordNotMatch         = errors.New("Password not match")
	ErrUserNotFound             = errors.New("User not found")
	ErrCannotRetrieveExpiration = errors.New("Cannot retireve expiration from token")
	ErrTokenExpired             = errors.New("Token expired")
	ErrResetTokenExpired        = errors.New("Reset token expired")
	ErrNoPasswordResetRequested = errors.New("No password request")
)

type AuthProvider interface {
	SignUp(user User) error
	SignIn(email, password string) (User, error)
	ActivateUser(activationToken string) error
	RequestUserActivationFor(email string) (string, error)
}

type PasswordManager interface {
	RequestPasswordResetFor(email string) (string, error)
	ResetPasswordBy(token, newpass string) error
}

type MgoAuthProvider struct {
	store DataStorage
}

func (m *MgoAuthProvider) SignUp(user User) error {
	var err error
	user.Password, err = encryptPassword(user.Password)
	err = m.store.InsertUser(user)
	return err
}

func (m *MgoAuthProvider) SignIn(email, password string) (User, error) {
	user, err := m.store.UserByEmail(email)
	if err != nil {
		return user, err
	}
	err = verifyUser(user, password)
	if err != nil {
		return user, err
	}
	return user, err
}

func (m *MgoAuthProvider) RequestUserActivationFor(email string) (string, error) {
	user, err := m.store.UserByEmail(email)
	if err != nil {
		return "", err
	}
	return m.storeActivity(user, USER_ACTIVATION)
}

func (m *MgoAuthProvider) ActivateUser(activationToken string) error {
	activity, err := m.store.GetActivityByToken(activationToken)
	if err != nil {
		return err
	}

	if len(activity.Token) == 0 || activity.Type != USER_ACTIVATION {
		return ErrNoPasswordResetRequested
	}

	now := time.Now().Unix()

	if activity.Expiration < now || activity.Used != int64(0) {
		return ErrResetTokenExpired
	}

	var user User
	user, err = m.store.UserByID(activity.User)
	if len(user.Email) == 0 {
		return ErrUserNotFound
	}

	user.Activated = true

	err = m.store.UpdateUser(user)
	if err == nil {
		activity.Used = now
		err = m.store.UpdateActivity(&activity)
	}

	return err
}

func (m *MgoAuthProvider) RequestPasswordResetFor(email string) (string, error) {
	user, err := m.store.UserByEmail(email)
	if err != nil {
		return "", err
	}
	return m.storeActivity(user, PASSWORD_RESET)
}

func (m *MgoAuthProvider) ResetPasswordBy(activityToken, newpass string) error {
	activity, err := m.store.GetActivityByToken(activityToken)
	if err != nil {
		return err
	}

	if len(activity.Token) == 0 || activity.Type != PASSWORD_RESET {
		return ErrNoPasswordResetRequested
	}

	now := time.Now().Unix()

	if activity.Expiration < now || activity.Used != int64(0) {
		return ErrResetTokenExpired
	}

	var user User
	user, err = m.store.UserByID(activity.User)
	if len(user.Email) == 0 {
		return ErrUserNotFound
	}

	encPass, encErr := encryptPassword(newpass)
	if encErr != nil {
		return encErr
	}
	user.Password = encPass

	err = m.store.UpdateUser(user)
	if err == nil {
		activity.Used = now
		err = m.store.UpdateActivity(&activity)
	}

	return err
}

func (m *MgoAuthProvider) storeActivity(user User, activityType string) (string, error) {
	now := time.Now()
	activity := &Activity{
		Type:       activityType,
		Token:      uuid.NewV4().String(),
		Time:       now.Unix(),
		User:       user.Id.Hex(),
		Expiration: now.Add(24 * time.Hour).Unix(),
	}
	err := m.store.InsertActivity(activity)

	if err != nil {
		return "", nil
	}
	return activity.Token, nil
}

func NewAuthProvider(store DataStorage) *MgoAuthProvider {
	provider := &MgoAuthProvider{
		store,
	}
	return provider
}

func comparePasswordHash(passHash, plainpassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(passHash), []byte(plainpassword))
	if err != nil {
		return false
	}
	return true
}

func encryptPassword(password string) (string, error) {
	bcrOut, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	output := string(bcrOut)
	return output, err
}

func verifyUser(user User, password string) error {
	if user.Email == "" {
		return ErrUserNotFound
	}
	if !(user.Expiration > time.Now().Unix()) {
		return ErrUserExpired
	}
	passOk := comparePasswordHash(user.Password, password)
	if !passOk {
		return ErrPasswordNotMatch
	}
	return nil
}
