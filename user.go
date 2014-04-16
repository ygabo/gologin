// This is from the martini-contrib example
// but this is using mysql instead of sqlite3
// For learning purposes only.
package main

import (
	rethink "github.com/dancannon/gorethink"
	"github.com/martini-contrib/sessionauth"
	"time"
)

type MyUserModel struct {
	Id            string `form:"id" gorethink:"id,omitempty"`
	Email         string `form:"email" gorethink:"email"`
	Password      string `form:"password" gorethink:"password"`
	Username      string `form:"name" gorethink:"username,omitempty"`
	Created       time.Time
	authenticated bool `form:"-" gorethink:"-"`
}

// GetAnonymousUser should generate an anonymous user model
// for all sessions. This should be an unauthenticated 0 value struct.
func GenerateAnonymousUser() sessionauth.User {
	return &MyUserModel{}
}

// Login will preform any actions that are required to make a user model
// officially authenticated.
func (u *MyUserModel) Login() {
	// Update last login time
	// Add to logged-in user's list
	// etc ...
	u.authenticated = true
}

// Logout will preform any actions that are required to completely
// logout a user.
func (u *MyUserModel) Logout() {
	// Remove from logged-in user's list
	// etc ...
	u.authenticated = false
}

func (u *MyUserModel) IsAuthenticated() bool {
	return u.authenticated
}

func (u *MyUserModel) UniqueId() interface{} {
	return u.Id
}

// GetById will populate a user object from a database model with
// a matching id.
func (u *MyUserModel) GetById(id interface{}) error {

	row, err := rethink.Table("user").Get(id).RunRow(dbSession)
	if err != nil {
		return err
	}
	if !row.IsNil() {
		if err := row.Scan(&u); err != nil {
			return err
		}
	}
	return nil
}
