package auth

import "golang.org/x/crypto/bcrypt"

// User struct holds user data
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash,omitempty"`
}

// Hash hashes plaintext password of user
func Hash(user User) (User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		return User{}, err
	}
	return User{
		Username: user.Username,
		Hash:     string(hash),
	}, nil
}

// CheckHash compares plain text candidate password to hashed password obtained from getRegistered closure
func CheckHash(candidate User, getRegistered func() (User, error)) error {
	registered, err := getRegistered()
	if err != nil {
		return err
	}

	return bcrypt.CompareHashAndPassword([]byte(registered.Hash), []byte(candidate.Password))
}
