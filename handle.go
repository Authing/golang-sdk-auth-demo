package main

import (
	// "fmt"
	"encoding/json"
	"fmt"
	"log"

	// "time"

	"github.com/Authing/authing-golang-sdk/authentication"
	"github.com/valyala/fasthttp"
)
const htmlNoLogin = `<h2>欢迎使用 Authing golang SDK</h2>
> <a href="/">/</a><br>
> <a href="/login">登录</a><br>`
const htmlLogined = `<h2>登录成功</h2>
> <a href="/logout">退出登录</a><br>
> <a href="/me">调用获取用户信息接口(IDToken中已经含有用户信息了，这个地方就是做一个演示)</a><br>
> <a href="/show">打印会话信息</a><br>`
// index handler
func indexHandler(ctx *fasthttp.RequestCtx) {
	
	
	ctx.SetContentType("text/html;charset=utf-8")
	ctx.SetBodyString(htmlNoLogin)
}



func loginHandler(ctx *fasthttp.RequestCtx) {
	store, err := serverSession.Get(ctx)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	defer func() {
		if err := serverSession.Save(ctx, store); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		}
	}()
	// 正式使用时将 state 设置为有意的上下文数据
	state := RandStringImpr(16)
	nonce := RandStringImpr(16)
	scope := "openid profile offline_access"
	store.Set("state", state)
	store.Set("nonce", nonce)
	var result authentication.AuthUrlResult
	result, err = authClient.BuildAuthUrl(&authentication.AuthURLParams{
		State: state,
		Scope: scope,
		Nonce: nonce,
	})
	if err != nil {
		log.Fatal(err)
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	ctx.Redirect(result.Url, 302)
}

func callbackHandler(ctx *fasthttp.RequestCtx) {
	args := ctx.QueryArgs()
	code := string(args.Peek("code"))
	if code == "" {
		ctx.Error("code不能为空", 400)
		return
	}
	store, err := serverSession.Get(ctx)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	defer func() {
		if err := serverSession.Save(ctx, store); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		}
	}()
	stateInStore := store.Get("state")
	if stateInStore == nil {
		ctx.Error("会话数据为空", 403)
		return
	}
	state := string(args.Peek("state"))
	if state != stateInStore {
		log.Fatalln(state, stateInStore)
		ctx.Error("非法跨站请求", 401)
		return
	}
	nonceInStore := store.Get("nonce")
	if nonceInStore == nil {
		ctx.Error("会话数据为空", 403)
		return
	}
	var loginState *authentication.LoginState
	loginState, err = authClient.GetLoginStateByAuthCode(&authentication.CodeToTokenParams{
		Code: code,
	})
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	if loginState.ParsedIDToken.Nonce != nonceInStore {
		ctx.Error("nonce参数验证不通过", 402)
		log.Fatalln(loginState.ParsedIDToken.Nonce, nonceInStore)
		return
	}
	var bytes []byte
	bytes, err = json.Marshal(loginState)
	if err != nil {
		ctx.Error("序列化token失败", fasthttp.StatusInternalServerError)
		return
	}
	store.Flush()
	store.Set("user", string(bytes))
	

	ctx.SetContentType("text/html;charset=utf-8")
	ctx.SetBodyString(htmlLogined)
}

func showHandler(ctx *fasthttp.RequestCtx) {
	store, err := serverSession.Get(ctx)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	defer func() {
		if err := serverSession.Save(ctx, store); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		}
	}()
	user := store.Get("user").(string)
	ctx.SetBodyString(user)
}

func logoutHandler(ctx *fasthttp.RequestCtx) {
	store, err := serverSession.Get(ctx)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	defer func() {
		if err := serverSession.Save(ctx, store); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		}
	}()
	user := store.Get("user").(string)
	var loginState authentication.LoginState
	err = json.Unmarshal([]byte(user), &loginState)
	if err != nil {
		log.Fatalf("无法序列化：%s", user)
		ctx.Error("反序列化会话数据失败", fasthttp.StatusInternalServerError)
		return
	}
	store.Delete("user")
	var url string
	url, err = authClient.BuildLogoutUrl(&authentication.LogoutURLParams{
		IDTokenHint: loginState.IdToken,
		RedirectUri: fmt.Sprintf("http://localhost:%d", port),
	})
	if err != nil {
		log.Fatalf("构建退出url失败：%v", err)
		ctx.Error("构建退出url失败", fasthttp.StatusInternalServerError)
		return
	}
	ctx.Redirect(url, 302)
}

func userInfoHandler(ctx *fasthttp.RequestCtx) {
	store, err := serverSession.Get(ctx)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	defer func() {
		if err := serverSession.Save(ctx, store); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		}
	}()
	user := store.Get("user").(string)
	if (user == "") {
		ctx.Error("用户尚未登录", 403)
		return
	}
	var loginState authentication.LoginState
	err = json.Unmarshal([]byte(user), &loginState)
	if err != nil {
		log.Fatalf("无法序列化：%s", user)
		ctx.Error("反序列化会话数据失败", fasthttp.StatusInternalServerError)
		return
	}
	var info *authentication.UserInfo
	info, err = authClient.GetUserInfo(loginState.AccessToken)
	if err != nil {
		ctx.Error(fmt.Sprintf("获取用户数据失败%v", err), fasthttp.StatusInternalServerError)
		return
	}
	var bytes []byte
	bytes, err = json.Marshal(info)
	if err != nil {
		ctx.Error(fmt.Sprintf("序列化用户数据失败%v", err), fasthttp.StatusInternalServerError)
		return
	}
	ctx.SetBodyString(string(bytes))
}

