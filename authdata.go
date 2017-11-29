package authfile

import (
	"errors"
	"sync"
	"sync/atomic"

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
	cost uint64
	m    *sync.RWMutex
}

func newAuthData() *authData {
	return &authData{
		data: make(map[string][]byte),
		m:    new(sync.RWMutex),
	}
}

func (ad *authData) setCost(cost uint64) {
	atomic.StoreUint64(&ad.cost, cost)
}

func (ad *authData) getCost() uint64 {
	return atomic.LoadUint64(&ad.cost)
}

func (ad *authData) get(username string) []byte {
	ad.m.RLock()
	defer ad.m.RUnlock()
	if pass, ok := ad.data[username]; ok {
		return pass
	}
	return nil
}

func (ad *authData) set(username string, passwordHash []byte) {
	ad.m.Lock()
	defer ad.m.Unlock()
	ad.data[username] = passwordHash
	return
}

func (ad *authData) delete(m msgDelete) {
	p := ad.get(m.username)
	if p != nil {
		ad.m.Lock()
		defer ad.m.Unlock()
		delete(ad.data, m.username)
		m.r <- nil
		return
	}
	m.r <- ErrUserDoesNotExist
	return
}

func (ad *authData) add(m msgAdd) {
	p := ad.get(m.username)
	if p != nil {
		m.r <- ErrUserExists
		return
	}
	cost := int(ad.getCost())
	bhash, err := bcrypt.GenerateFromPassword([]byte(m.password), cost)
	if err == nil {
		ad.set(m.username, bhash)
	}
	m.r <- err
	return
}

func (ad *authData) modify(m msgModify) {
	p := ad.get(m.username)
	if p == nil {
		m.r <- ErrUserDoesNotExist
		return
	}
	cost := int(ad.getCost())
	bhash, err := bcrypt.GenerateFromPassword([]byte(m.password), cost)
	if err == nil {
		ad.set(m.username, bhash)
	}
	m.r <- err
	return
}

func (ad *authData) verifyModify(m msgVerifyModify) {
	pass := ad.get(m.username)
	if pass == nil {
		m.r <- ErrUserDoesNotExist
		return
	}
	if bcrypt.CompareHashAndPassword(pass, []byte(m.oldpassword)) != nil {
		m.r <- ErrAuthenticationFailed
		return
	}
	cost := int(ad.getCost())
	bhash, err := bcrypt.GenerateFromPassword([]byte(m.newpassword), cost)
	if err != nil {
		m.r <- err
		return
	}
	ad.set(m.username, bhash)
	m.r <- nil
	return
}

func (ad *authData) authenticate(m msgAuthenticate) {
	pass := ad.get(m.username)
	if pass == nil {
		m.r <- ErrUserDoesNotExist
		return
	}
	if bcrypt.CompareHashAndPassword(pass, []byte(m.password)) != nil {
		m.r <- ErrAuthenticationFailed
		return
	}
	m.r <- nil // Return early, allow session to continue.
	cost := int(ad.getCost())
	if pcost, err := bcrypt.Cost(pass); err == nil {
		if pcost < cost {
			bhash, err := bcrypt.GenerateFromPassword([]byte(m.password), cost)
			if err == nil {
				ad.set(m.username, bhash)
			}
		}
	}
	return
}
