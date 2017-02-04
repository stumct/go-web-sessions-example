package main

import (
	"log"
	"net/http"
	"time"

	uuid "github.com/satori/go.uuid"
)

// Most of the functionality here should be calling out to a database.
// Everything is currently done in memory for example purposes.

// MaxSessionAge defines the maximum age of the session in seconds.
const MaxSessionAge = 300

// SessionDB describes a SessionDB object.
type SessionDB struct {
	sessions map[string]Session
}

// Get a Session from the database from a supplied sessionID.
// Returns a pointer to a Session.
func (db *SessionDB) Get(sessionID string) (*Session, error) {
	if s, ok := db.sessions[sessionID]; ok {
		return &s, nil
	}
	return nil, ErrorSessionDoesntExist{}
}

// Create will create a new session in the database using the supplied id as a key.
// Also sets a cookie in the response.
func (db *SessionDB) Create(w http.ResponseWriter, r *http.Request, id int) error {
	// Create a new session and add it to the database.
	s := Session{
		SessionID: uuid.NewV4().String(),
		Time:      time.Now(),
		UserID:    id,
	}
	db.sessions[s.SessionID] = s

	// Create a new cookie.
	c := &http.Cookie{
		Name:   "session",
		Value:  s.SessionID,
		MaxAge: MaxSessionAge,
		//Secure:   true,
		HttpOnly: true,
	}
	// Add the cookie to the response.
	http.SetCookie(w, c)
	return nil
}

// Delete a session from the database.
// Reads the session cookie from the request to obtain the session id.
// Sets a new cookie which will expire.
func (db *SessionDB) Delete(w http.ResponseWriter, r *http.Request) error {

	// Get the Session from the SessionID in the cookie
	c, err := r.Cookie("session")
	if err != nil {
		return err
	}

	// Delete the session
	delete(db.sessions, c.Value)

	// Return an expired cookie
	nc := &http.Cookie{
		Name:   "session",
		Value:  c.Value,
		MaxAge: -1,
		//Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, nc)
	return nil
}

// Extend will extend the current session to the MaxSessionAge.
// Reads the current session from the request and returns and updated cookie.
func (db *SessionDB) Extend(w http.ResponseWriter, r *http.Request) error {
	// Get the Session from the SessionID in the cookie
	c, err := r.Cookie("session")
	if err != nil {
		return err
	}

	// Find the session and reset the time.
	if s, ok := db.sessions[c.Value]; ok {
		s.Time = time.Now()
		db.sessions[c.Value] = s
	}

	// Return an extended cookie
	nc := &http.Cookie{
		Name:   "session",
		Value:  db.sessions[c.Value].SessionID,
		MaxAge: MaxSessionAge,
		//Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, nc)
	return nil
}

// IsAuthenticated will check if a user is authenticated.
// If true then also extend the session.
func (db *SessionDB) IsAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	// Check if the request has a session cookie.
	// If there is no cookie then return false.
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}

	// Check if the sessionid in the cookie is valid.
	// If it is not valid return false.
	_, err = db.Get(c.Value)
	if err != nil {
		return false
	}

	// Otherwise the session must be valid. Extend it then return true
	err = db.Extend(w, r)
	if err != nil {
		log.Println("Unable to extend session:", err)
	}
	return true
}

// Session describes a Session object.
type Session struct {
	SessionID string
	Time      time.Time
	UserID    int
}

type ErrorSessionDoesntExist struct {
}

func (ErrorSessionDoesntExist) Error() string {
	return "Session does not exist"
}
