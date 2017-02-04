package main

import (
	"html/template"
	"log"
	"net/http"
)

// Setup global variables for our sessions, users and templates.
var tpl *template.Template
var usersDB *UsersDB
var sessionDB *SessionDB

// init will initialise the sessions, users and templates.
func init() {
	tpl = template.Must(template.ParseGlob("./templates/*.html"))
	usersDB = &UsersDB{map[int]User{}}
	sessionDB = &SessionDB{map[string]Session{}}
}

// main is the main entry point to the application.
// Defines the handlers and starts the server.
func main() {
	http.HandleFunc("/", index)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
	http.HandleFunc("/account", account)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// getUserAndSessionFromSessionCookie returns a User and Session object based on the request cookie.
func getUserAndSessionFromSessionCookie(r *http.Request) (*User, *Session, error) {
	// Get the Session from the SessionID in the cookie
	c, err := r.Cookie("session")
	if err != nil {
		return nil, nil, err
	}
	s, err := sessionDB.Get(c.Value)
	if err != nil {
		return nil, nil, err
	}

	// Get the user via the UserID in the Session
	u, err := usersDB.Get(s.UserID)
	if err != nil {
		return nil, nil, err
	}
	return u, s, nil
}

// index route handler.
func index(w http.ResponseWriter, r *http.Request) {
	// If the user is already authenticated then redirect.
	if ok := sessionDB.IsAuthenticated(w, r); ok {
		// Get the user out of the session
		u, s, err := getUserAndSessionFromSessionCookie(r)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Return the account page.
		tpl.ExecuteTemplate(w, "index.html", struct {
			User       *User
			Session    *Session
			IsLoggedIn bool
		}{
			u,
			s,
			true,
		})
		return
	}
	tpl.ExecuteTemplate(w, "index.html", nil)
}

// signup route handler.
func signup(w http.ResponseWriter, r *http.Request) {
	// If the user is already authenticated then redirect.
	if ok := sessionDB.IsAuthenticated(w, r); ok {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	// If the Method is POST then handle the form values
	if r.Method == http.MethodPost {
		e := r.FormValue("email")
		f := r.FormValue("firstName")
		l := r.FormValue("lastName")
		p := r.FormValue("password")
		cp := r.FormValue("confirmPassword")

		// Check if the supplied email already exists.
		// If it does return to the signup page and present the error.
		err := usersDB.CheckEmailExists(e)
		if err != nil {
			tpl.ExecuteTemplate(w, "signup.html", struct {
				Error string
			}{
				err.Error(),
			})
			return
		}

		// Otherwise create the new user, session and cookie.
		// Then redirect.
		id, err := usersDB.Add(e, f, l, p, cp)
		if err != nil {
			tpl.ExecuteTemplate(w, "signup.html", struct {
				Error string
			}{
				err.Error(),
			})
			return
		}
		err = sessionDB.Create(w, r, id)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	// Return the signup page.
	tpl.ExecuteTemplate(w, "signup.html", nil)
}

// login route handler.
func login(w http.ResponseWriter, r *http.Request) {
	// If the user is already authenticated then redirect.
	if ok := sessionDB.IsAuthenticated(w, r); ok {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	// If the Method is POST then handle the form values
	if r.Method == http.MethodPost {
		e := r.FormValue("email")
		p := r.FormValue("password")

		// Attempt to login using the supplied credentials.
		// Return the login page with an error if they are invalid.
		u, err := usersDB.Login(e, p)
		if err != nil {
			tpl.ExecuteTemplate(w, "login.html", struct {
				Error string
			}{
				err.Error(),
			})
			return
		}

		// Otherwise create a session and cookie
		err = sessionDB.Create(w, r, u.UserID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		// Then redirect.
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}

	// Return the login page.
	tpl.ExecuteTemplate(w, "login.html", nil)
}

// logout route handler.
func logout(w http.ResponseWriter, r *http.Request) {
	// If the user is not authenticated then redirect.
	if ok := sessionDB.IsAuthenticated(w, r); !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Delete the session
	err := sessionDB.Delete(w, r)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
	// Redirect back home.
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return

}

// account route handler.
func account(w http.ResponseWriter, r *http.Request) {
	// If the user is not authenticated then return a 401.
	if ok := sessionDB.IsAuthenticated(w, r); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get the user out of the session
	u, s, err := getUserAndSessionFromSessionCookie(r)
	if err != nil {
		log.Println(err)
		return
	}

	// Return the account page.
	tpl.ExecuteTemplate(w, "account.html", struct {
		User       *User
		Session    *Session
		IsLoggedIn bool
	}{
		u,
		s,
		true,
	})
}
