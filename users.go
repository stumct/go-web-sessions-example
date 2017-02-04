package main

import "golang.org/x/crypto/bcrypt"

// Most of the functionality here should be calling out to a database.
// Everything is currently done in memory for example purposes.

// Keep track of the last UserID created
var lastUserID int

// UsersDB describes a UsersDB object.
type UsersDB struct {
	users map[int]User
}

// CheckEmailExists will check if the supplied email has already been registered in the database.
func (db *UsersDB) CheckEmailExists(email string) error {
	// Check if the user is already in the database.
	for _, u := range db.users {
		if u.Email == email {
			return ErrorEmailAlreadyRegistered{}
		}
	}
	return nil
}

// Add will add a new user to the database.
// Handles checking for password equality and hashing.
func (db *UsersDB) Add(email string, firstName string, lastName string, password string, confirmPassword string) (int, error) {
	// Compare the passwords for equality. Return an error if they do not match.
	if password != confirmPassword {
		return 0, ErrorPasswordsDoNotMatch{}
	}
	// Hash the password.
	pass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return 0, err
	}

	// Create the user.
	u := User{
		UserID:    lastUserID + 1,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		password:  pass,
	}
	db.users[u.UserID] = u

	// Return the UserID.
	return u.UserID, nil
}

// Login will log the user in by checking the email and password are valid.
func (db *UsersDB) Login(email string, password string) (*User, error) {
	// Find the user by email.
	for _, u := range db.users {
		if u.Email == email {
			// Compare the supplied password to the stored hash.
			err := bcrypt.CompareHashAndPassword(u.password, []byte(password))
			if err != nil {
				return nil, ErrorIncorrectCredentials{}
			}
			// Return the user.
			return &u, nil
		}
	}
	// If no user is found return an error.
	return nil, ErrorIncorrectCredentials{}
}

// Get will return a user if the supplied id is valid.
func (db *UsersDB) Get(id int) (*User, error) {
	// Find the user by id.
	if u, ok := db.users[id]; ok {
		return &u, nil
	}
	return nil, ErrorUserNotFound{}
}

// User describes a user object.
type User struct {
	UserID    int
	Email     string
	FirstName string
	LastName  string
	password  []byte
}

type ErrorIncorrectCredentials struct {
}

func (ErrorIncorrectCredentials) Error() string {
	return "Incorrect Email or Password."
}

type ErrorPasswordsDoNotMatch struct {
}

func (ErrorPasswordsDoNotMatch) Error() string {
	return "Passwords do not match."
}

type ErrorUserNotFound struct {
}

func (ErrorUserNotFound) Error() string {
	return "No user has been found."
}

type ErrorEmailAlreadyRegistered struct {
}

func (ErrorEmailAlreadyRegistered) Error() string {
	return "A user has already registered with that email address."
}
