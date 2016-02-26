package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"text/template"

	log "github.com/Sirupsen/logrus"
	"github.com/nats-io/nats"
	"github.com/sebest/logrusly"
	"github.com/sohlich/nats-proxy"
	"github.com/suricatatalk/guardian/auth"
	"github.com/suricatatalk/mail/client"

	"github.com/kelseyhightower/envconfig"

	// "github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	// "github.com/markbates/goth/providers/twitter"
)

const (
	ServiceName = "gateway"
	TokenHeader = "X-AUTH"

	//Configuration keys
	KeyLogly = "LOGLY_TOKEN"
)

var (
	ErrInavelidActivationToken = errors.New("Invalid activation token")
	authProvider               auth.AuthProvider
	passManager                auth.PasswordManager
	appCfg                     *AppConfig
)

var (
	mailClient         client.MailClient
	activationComposer client.MessageComposer
	passResetComposer  client.MessageComposer
)

type AppConfig struct {
	Host   string `default:"127.0.0.1"`
	Port   string `default:"1111"`
	Name   string `default:"core1"`
	Domain string `default:"suricata.cleverapps.io"`
}

type MgoConfig struct {
	URI string `default:"127.0.0.1:27017"`
	DB  string `default:"surikata"`
}

type NatsConfig struct {
	Endpoint string `default:"nats://localhost:4222"`
}

// loadConfiguration loads the configuration of application
func loadConfiguration(app *AppConfig, mgo *MgoConfig, nats *NatsConfig) {
	err := envconfig.Process(ServiceName, app)
	if err != nil {
		log.Panicln(err)
	}
	err = envconfig.Process("mongodb", mgo)
	if err != nil {
		log.Panicln(err)
	}
	err = envconfig.Process("nats", nats)
	if err != nil {
		log.Panicln(err)
	}
	if len(os.Getenv(KeyLogly)) > 0 {
		log.Println("Loading logly token %s", os.Getenv(KeyLogly))
		hook := logrusly.NewLogglyHook(os.Getenv(KeyLogly),
			app.Host,
			log.InfoLevel,
			app.Name)
		log.AddHook(hook)
	}
}

func main() {
	//TODO os.Getenv("DOMAIN")
	configureSocial()
	// Load all configuration
	appCfg = &AppConfig{}
	mgoCfg := &MgoConfig{}
	natsCfg := &NatsConfig{}
	loadConfiguration(appCfg, mgoCfg, natsCfg)

	log.Infoln("Initializing NatsMailClient")
	initMail()
	var mailErr error
	mailClient, mailErr = client.NewNatsMailClient(natsCfg.Endpoint)
	if mailErr != nil {
		log.Errorf("Cannot initialize mail client: %s", mailErr.Error())
	}
	//Mongo configuration
	log.Infoln("Loading configuration of MongoDB")
	mgoStorage := auth.NewMgoStorage()
	mgoStorage.ConnectionString = mgoCfg.URI
	mgoStorage.Database = mgoCfg.DB
	err := mgoStorage.OpenSession()
	if err != nil {
		log.Panic(err)
	}
	log.Infoln("Initializing auth provider")
	mgoAuthProvider := auth.NewAuthProvider(mgoStorage)
	authProvider = mgoAuthProvider
	passManager = mgoAuthProvider

	log.Infoln("Initializing reverse proxy")

	log.Infoln("Registering handlers")
	//Handle login and register

	clientConn, _ := nats.Connect(natsCfg.Endpoint)
	defer clientConn.Close()
	mux, natsErr := natsproxy.NewNatsClient(clientConn)
	if natsErr != nil {
		log.Panic("Cannot initialize NATS client")
	}
	mux.GET("/activate/:activateToken", activateHandler)
	mux.POST("/login", loginHandler)
	mux.POST("/register", registerHandler)

	mux.POST("/requestpasswordreset", requestPasswordResetHandler)
	mux.POST("/resetpassword/:resettoken", passwordResetHandler)
	// mux.Get("/auth/{provider}/callback", handleSocialLogin)
	// mux.Get("/auth/{provider}", gothic.BeginAuthHandler)
	//else handle via proxy

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Press Ctrl+C for exit.")
	<-sig
}

func initMail() {
	subjectTemp, _ := template.New("activate_subject").Parse("Suricata: Registration confirmation")
	messageTemp, _ := template.New("activate_message").Parse("Please confirm the registration on Suricata Talk website with click on this link {{.ConfirmationLink}}")
	activationComposer = &client.SuricataMessageComposer{
		subjectTemp,
		messageTemp,
	}

	subjectTemp, _ = template.New("passreset_subject").Parse("Suricata: Password reset")
	messageTemp, _ = template.New("passreset_message").Parse("Reset the password on following link {{.ResetLink}}")
	passResetComposer = &client.SuricataMessageComposer{
		subjectTemp,
		messageTemp,
	}
}

func configureSocial() {
	//No Op
}

func loginHandler(c *natsproxy.Context) {
	payload := struct {
		Email    string
		Password string
	}{}

	decodeErr := json.Unmarshal(c.Request.Body, &payload)
	if decodeErr != nil {
		c.JSON(http.StatusBadRequest, decodeErr.Error())
		return
	}

	user, err := authProvider.SignIn(payload.Email, payload.Password)
	if err != nil && err != auth.ErrPasswordNotMatch {
		c.JSON(http.StatusForbidden, err.Error())
		return
	}

	marshUser, jsonErr := json.Marshal(user)
	if jsonErr != nil {
		c.JSON(http.StatusInternalServerError, jsonErr.Error())
		return
	}

	c.Response.Header.Set(TokenHeader, string(marshUser))
}

func registerHandler(c *natsproxy.Context) {

	user := auth.NewInactiveUser()
	decodeErr := json.Unmarshal(c.Request.Body, &user)
	if decodeErr != nil {
		c.JSON(http.StatusBadRequest, decodeErr.Error())
		return
	}
	signUpErr := authProvider.SignUp(user)
	if signUpErr != nil {
		c.JSON(http.StatusBadRequest, signUpErr.Error())
		return
	}

	actToken, err := authProvider.RequestUserActivationFor(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, "Cannot request user activation")
		return
	}
	sendActivationMailToUser(user.Email, actToken)

	// jsonVal, _ := json.Marshal(user)
	c.JSON(http.StatusOK, user)
}

func activateHandler(c *natsproxy.Context) {
	log.Println("Activate handler")
	token := c.PathVariable("activateToken")
	if len(token) != 36 {
		c.JSON(405, "Token not valid")
		c.Abort()
		return
	}
	authProvider.ActivateUser(token)
}

func requestPasswordResetHandler(c *natsproxy.Context) {
	log.Println("Request password reset")
	email := c.Request.Form.Get("email")
	if len(email) == 0 {
		log.Infoln("Parameter \"email\" not found")
		c.JSON(http.StatusNotFound, "email param not found")
		return
	}
	token, err := passManager.RequestPasswordResetFor(email)
	if err != nil {
		log.Error(err)
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		return
	}
	//TODO send mail with token
	err = sendPasswordResetMail(email, token)
	if err != nil {
		log.Error("Could not send password reset for mail: %s", email)
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
		return
	}
}

func passwordResetHandler(c *natsproxy.Context) {
	tkn := c.PathVariable("resettoken")
	pass := c.Request.Form.Get("password")
	err := passManager.ResetPasswordBy(tkn, pass)
	if err == auth.ErrResetTokenExpired {
		c.JSON(http.StatusForbidden, "Expired")

	} else if err != nil {
		log.Error(err)
		c.JSON(http.StatusInternalServerError, "Internal Server Error")
	}
	c.JSON(http.StatusOK, "Password reset")
}

func handleSocialLogin(rw http.ResponseWriter, req *http.Request) {
	log.Println(gothic.GetState(req))
	socialUser, err := gothic.CompleteUserAuth(rw, req)
	if err != nil {
		log.Println(err)
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	user := auth.User{}
	user.UserID = socialUser.UserID
	user.Email = socialUser.Email

	log.Println(socialUser.UserID)
	log.Println(socialUser.AccessToken)
	log.Println(socialUser.NickName)
}

func sendActivationMailToUser(email, token string) error {
	messageStruct := struct{ ConfirmationLink string }{fmt.Sprintf("http://%s/activate/%s", appCfg.Domain, token)}
	subject := activationComposer.ComposeSubject(struct{}{})
	message := activationComposer.ComposeMessage(messageStruct)
	return mailClient.SendMail(email, subject, message)
}

func sendPasswordResetMail(email, token string) error {
	messageStruct := struct{ ResetLink string }{fmt.Sprintf("http://%s/resetpassword/%s", appCfg.Domain, token)}
	subject := passResetComposer.ComposeSubject(struct{}{})
	message := passResetComposer.ComposeMessage(messageStruct)
	return mailClient.SendMail(email, subject, message)
}
