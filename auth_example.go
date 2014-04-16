// This from the martini-contrib sessionauth example,
// but this is using RethinkDB instead of sqlite3. For personal learning purposes only.

// Auth example is an example application which requires a login
// to view a private link. The username is "yelnil@example.coms" and the password
// is "qwe".
package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"fmt"
	rethink "github.com/dancannon/gorethink"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/binding"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessionauth"
	"github.com/martini-contrib/sessions"
	"log"
	"net/http"
)

var (
	dbSession *rethink.Session
)

func init() {

	// Assumes there's a rethinkdb instance running locally with db called 'todo'
	// Db has table called "user" with.
	// "yelnil@example.com" with password "qwe"
	var dbError error
	dbSession, dbError = rethink.Connect(rethink.ConnectOpts{
		Address:  "localhost:4444",
		Database: "todo"})
	if dbError != nil {
		log.Fatalln(dbError.Error())
	}

	// Testing purposes: query myself.
	me := MyUserModel{Email: "yelnil@example.com"}
	hpass, _ := bcrypt.GenerateFromPassword([]byte("qwe"), bcrypt.DefaultCost)
	me.Password = string(hpass)
	row, _ := rethink.Table("user").Filter(rethink.Row.Field("email").Eq(me.Email)).RunRow(dbSession)
	// I don't exist, insert me.
	if row.IsNil() {
		rethink.Table("user").Insert(me).RunWrite(dbSession)
	}
}

func main() {
	store := sessions.NewCookieStore([]byte("secret123"))
	m := martini.Classic()
	m.Use(render.Renderer())

	// Default our store to use Session cookies, so we don't leave logged in
	// users roaming around
	store.Options(sessions.Options{
		MaxAge: 0,
	})
	m.Use(sessions.Sessions("my_session", store))
	m.Use(sessionauth.SessionUser(GenerateAnonymousUser))
	sessionauth.RedirectUrl = "/new-login"
	sessionauth.RedirectParam = "new-next"

	m.Get("/", func(r render.Render) {
		r.HTML(200, "index", nil)
	})

	m.Get("/new-login", func(r render.Render) {
		r.HTML(200, "login", nil)
	})

	m.Post("/new-login", binding.Bind(MyUserModel{}), func(session sessions.Session, userLoggingIn MyUserModel, r render.Render, req *http.Request) {

		var userInDb MyUserModel
		query := rethink.Table("user").Filter(rethink.Row.Field("email").Eq(userLoggingIn.Email))
		row, err := query.RunRow(dbSession)

		// TODO do flash errors
		if err == nil && !row.IsNil() {
			if err := row.Scan(&userInDb); err != nil {
				fmt.Println("Error scanning user in DB")
				r.Redirect(sessionauth.RedirectUrl)
				return
			}
		} else {
			fmt.Println("No email")
			r.Redirect(sessionauth.RedirectUrl)
			return
		}
		passworderr := bcrypt.CompareHashAndPassword([]byte(userInDb.Password), []byte(userLoggingIn.Password))
		if passworderr != nil {
			fmt.Println("Wrong Password")
			r.Redirect(sessionauth.RedirectUrl)
			return
		} else {
			err := sessionauth.AuthenticateSession(session, &userInDb)
			if err != nil {
				fmt.Println("Wrong Auth")
				r.JSON(500, err)
			}
			params := req.URL.Query()
			redirect := params.Get(sessionauth.RedirectParam)
			r.Redirect(redirect)
			return
		}
	})

	m.Get("/private", sessionauth.LoginRequired, func(r render.Render, user sessionauth.User) {
		r.HTML(200, "private", user.(*MyUserModel))
	})

	m.Get("/logout", sessionauth.LoginRequired, func(session sessions.Session, user sessionauth.User, r render.Render) {
		sessionauth.Logout(session, user)
		r.Redirect("/")
	})

	m.Run()
}
