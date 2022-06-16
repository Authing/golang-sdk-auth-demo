package main

import (
	"fmt"
	"log"
	"github.com/Authing/authing-golang-sdk/authentication"
	"github.com/fasthttp/router"
	"github.com/fasthttp/session/v2"
	"github.com/fasthttp/session/v2/providers/memory"
	"github.com/valyala/fasthttp"
)

var authClient *authentication.Client
var serverSession *session.Session
const port = 7001
const callbackPath = "/callback"

func init() {
	var err error
	authClient, err =  authentication.NewClient(&authentication.AuthenticationClientOptions{
		AppId:       "62a8570a85859e2390ef388f",
		AppSecret:   "ffe0ecad57823426e065a8c6d6bcd0b8",
		Domain:      "localtest.test2.authing-inc.co",
		RedirectUri: fmt.Sprintf("http://localhost:%d%s", port , callbackPath),
	})
	if err != nil {
		panic(err)
	}
	var provider session.Provider
	encoder := session.MSGPEncode
	decoder := session.MSGPDecode
	provider, err = memory.New(memory.Config{})
	if err != nil {
		panic(err)
	}
	cfg := session.NewDefaultConfig()
	cfg.EncodeFunc = encoder
	cfg.DecodeFunc = decoder
	serverSession = session.New(cfg)
	if err = serverSession.SetProvider(provider); err != nil {
		panic(err)
	}
	log.Print("init ok")
}

func main() {
	r := router.New()
	r.GET("/", indexHandler)
	r.GET("/login", loginHandler)
	r.GET("/callback", callbackHandler)
	r.GET("/show", showHandler)
	r.GET("/logout", logoutHandler)
	r.GET("/me", userInfoHandler)

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	log.Println("Session example server listen: http://" + addr)

	err := fasthttp.ListenAndServe(addr, r.Handler)
	if err != nil {
		log.Fatal(err)
	}
}