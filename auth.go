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
		Address:  "localhost:28015",
		Database: "todo"})
	if dbError != nil {
		log.Fatalln(dbError.Error())
	}

	// Testing purposes: query myself.
	me := MyUserModel{Email: "yelnil@example.com"}
	hpass, _ := bcrypt.GenerateFromPassword([]byte("qwe"), bcrypt.DefaultCost)
	me.Password = string(hpass)
	row, err := rethink.Table("user").Filter(rethink.Row.Field("email").Eq(me.Email)).RunRow(dbSession)
	if err != nil {
		fmt.Println(err)
	}
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

	m.Get("/register", func(session sessions.Session, r render.Render) {
		if session.Get(sessionauth.SessionKey) != nil {
			fmt.Println("Logged in already! Logout first.")
			r.HTML(200, "index", nil)
			return
		}
		r.HTML(200, "register", nil)
	})

	m.Post("/register", binding.Bind(MyUserModel{}), func(session sessions.Session, newUser MyUserModel, r render.Render, req *http.Request) {

		if session.Get(sessionauth.SessionKey) != nil {
			fmt.Println("Logged in already! Logout first.")
			r.HTML(200, "index", nil)
			return
		}

		var userInDb MyUserModel
		query := rethink.Table("user").Filter(rethink.Row.Field("email").Eq(newUser.Email))
		row, err := query.RunRow(dbSession)

		if err == nil && !row.IsNil() {
			// Register, error case.
			if err := row.Scan(&userInDb); err != nil {
				fmt.Println("Error reading DB")
			} else {
				fmt.Println("User already exists. Redirecting to login.")
			}

			r.Redirect(sessionauth.RedirectUrl)
			return
		} else { // User doesn't exist, continue with registration.
			if row.IsNil() {
				fmt.Println("User doesn't exist. Registering...")
			} else {
				fmt.Println(err)
			}
		}

		// Try to compare passwords
		pass1Hash, _ := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		pass2String := req.FormValue("confirmpassword")
		passErr := bcrypt.CompareHashAndPassword(pass1Hash, []byte(pass2String))

		if passErr != nil {
			fmt.Println("Error, passwords don't match.", passErr)
		} else { // passwords are the same, insert user to db
			newUser.Password = string(pass1Hash)
			rethink.Table("user").Insert(newUser).RunWrite(dbSession)
			fmt.Println("Register done. Try to login.")
		}

		r.Redirect(sessionauth.RedirectUrl)
	})

	m.Post("/new-login", binding.Bind(MyUserModel{}), func(session sessions.Session, userLoggingIn MyUserModel, r render.Render, req *http.Request) {
		var userInDb MyUserModel
		query := rethink.Table("user").Filter(rethink.Row.Field("email").Eq(userLoggingIn.Email))
		row, err := query.RunRow(dbSession)
		fmt.Println("logging in:", userLoggingIn.Email)
		// TODO do flash errors
		if err == nil && !row.IsNil() {
			if err := row.Scan(&userInDb); err != nil {
				fmt.Println("Error scanning user in DB")
				r.Redirect(sessionauth.RedirectUrl)
				return
			}
		} else {
			if row.IsNil() {
				fmt.Println("User doesn't exist")
			} else {
				fmt.Println(err)
			}
			r.Redirect(sessionauth.RedirectUrl)
			return
		}

		passErr := bcrypt.CompareHashAndPassword([]byte(userInDb.Password), []byte(userLoggingIn.Password))
		if passErr != nil {
			fmt.Println("Wrong Password")
			r.Redirect(sessionauth.RedirectUrl)
		} else {
			err := sessionauth.AuthenticateSession(session, &userInDb)
			if err != nil {
				fmt.Println("Wrong Auth")
				r.JSON(500, err)
			}
			params := req.URL.Query()
			redirect := params.Get(sessionauth.RedirectParam)
			r.Redirect(redirect)
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
