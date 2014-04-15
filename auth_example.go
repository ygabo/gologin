// This from the martini-contrib sessionauth example,
// but this is using MySQL instead of sqlite3. For personal learning purposes only.

// Auth example is an example application which requires a login
// to view a private link. The username is "testuser" and the password
// is "password".
package main

import (
	"database/sql"
	"github.com/coopernurse/gorp"
	"github.com/go-martini/martini"
	"github.com/martini-contrib/binding"
	"github.com/martini-contrib/render"
	"github.com/martini-contrib/sessionauth"
	"github.com/martini-contrib/sessions"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"net/http"
	"os"
	"fmt"

)

var dbmap *gorp.DbMap

func initDb() *gorp.DbMap {

	// Assumes there's a mysql server running locally with db called 'test'
	// has one row in it with 'testuser' and 'password' as pw
	// columns are: id, username, password

	db, err := sql.Open("mysql", "user:password@/test")
	if err != nil {
		log.Fatalln("Fail to create database", err)
	}

	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{"test", "UTF8"}}
	return dbmap
}

func main() {
	store := sessions.NewCookieStore([]byte("secret123"))
	dbmap = initDb()

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

	m.Post("/new-login", binding.Bind(MyUserModel{}), func(session sessions.Session, postedUser MyUserModel, r render.Render, req *http.Request) {
		
		// This isn't really proper auth.
		// When users register, do some sort of password encryption/hash and save the output in the DB. 
		// Afterwards, when they login, encrypt/hash their input password and compare it with the one in the DB.
		user := MyUserModel{}
		err := dbmap.SelectOne(&user, "SELECT * FROM users WHERE username=? and password=?", postedUser.Username, postedUser.Password)
		if err != nil {
			fmt.Println(err)
			r.Redirect(sessionauth.RedirectUrl)
			return
		} else {
			err := sessionauth.AuthenticateSession(session, &user)
			if err != nil {
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
