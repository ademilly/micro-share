package auth_test

import (
	"errors"
	"testing"

	"github.com/ademilly/micro-share/auth"
)

func TestHash(t *testing.T) {
	user := auth.User{Username: "test", Password: "1234"}

	hashUser, err := auth.Hash(user)
	if err != nil {
		t.Errorf("got error using auth.Hash: %v", err)
	}

	if hashUser.Username != user.Username {
		t.Errorf("name should not have changed, got %s, should be %s", hashUser.Username, user.Username)
	}

	if string(hashUser.Password) != "" {
		t.Errorf("hashUser Password field should be empty, got: %v", hashUser.Password)
	}

	if string(hashUser.Hash) == "" {
		t.Errorf("hashUser Hash field shout not be empty")
	}
}

func TestCheckHash(t *testing.T) {
	user := auth.User{Username: "test", Password: "1234"}

	err := auth.CheckHash(user, func() (auth.User, error) {
		return auth.Hash(user)
	})
	if err != nil {
		t.Errorf("hash does not match password: %v", err)
	}

	expected := errors.New("This should fail")
	err = auth.CheckHash(user, func() (auth.User, error) {
		return auth.User{}, expected
	})
	if err == nil {
		t.Errorf("err should not be nil, got %v, expected %v", err, expected)
	}
}
