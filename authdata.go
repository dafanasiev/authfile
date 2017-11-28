package authfile

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrUserDoesNotExist is returned if operating on a user that does not exist.
	ErrUserDoesNotExist = errors.New("authfile: User does not exist")
	// ErrUserExists is returned if trying to add a user that already exists.
	ErrUserExists = errors.New("authfile: User exists")
	// ErrAuthenticationFailed is returnd if the password does not match the user.
	ErrAuthenticationFailed = errors.New("authfile: Authentication failure")
)

type authData struct {
	data map[string][]byte
}

func newAuthData() *authData {
	return &authData{
		data: make(map[string][]byte),
	}
}

func (ad *authData) delete(m msgDelete) {
	if _, ok := ad.data[m.username]; ok {
		delete(ad.data, m.username)
		m.r <- nil
		return
	}
	m.r <- ErrUserDoesNotExist
}

func (ad *authData) add(m msgAdd, cost int) {
	if _, ok := ad.data[m.username]; ok {
		m.r <- ErrUserExists
		return
	}
	bhash, err := bcrypt.GenerateFromPassword([]byte(m.password), cost)
	if err == nil {
		ad.data[m.username] = bhash
	}
	m.r <- err
}

func (ad *authData) modify(m msgModify, cost int) {
	if _, ok := ad.data[m.username]; ok {
		bhash, err := bcrypt.GenerateFromPassword([]byte(m.password), cost)
		if err == nil {
			ad.data[m.username] = bhash
		}
		m.r <- err
		return
	}
	m.r <- ErrUserDoesNotExist
}

func (ad *authData) verifyModify(m msgVerifyModify, cost int) {
	if pass, ok := ad.data[m.username]; !ok {
		m.r <- ErrUserDoesNotExist
	} else if bcrypt.CompareHashAndPassword(pass, []byte(m.oldpassword)) != nil {
		m.r <- ErrAuthenticationFailed
	} else {
		bhash, err := bcrypt.GenerateFromPassword([]byte(m.newpassword), cost)
		if err != nil {
			m.r <- err
			return
		}
		ad.data[m.username] = bhash
		m.r <- nil
	}
	return
}

func (ad *authData) authenticate(m msgAuthenticate, cost int) {
	if pass, ok := ad.data[m.username]; !ok {
		m.r <- ErrUserDoesNotExist
	} else if bcrypt.CompareHashAndPassword(pass, []byte(m.password)) != nil {
		m.r <- ErrAuthenticationFailed
	} else {
		if pcost, err := bcrypt.Cost(pass); err == nil {
			if pcost < cost {
				bhash, err := bcrypt.GenerateFromPassword([]byte(m.password), cost)
				if err == nil {
					ad.data[m.username] = bhash
				}
			}
		}
		m.r <- nil
	}
	return
}
