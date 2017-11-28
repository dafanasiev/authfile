package authfile

import (
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	// ErrNoTransaction is returned if trying to load without a transaction
	ErrNoTransaction = errors.New("authfile: No transaction")
)

// InMemoryService implements an authentication service.
type InMemoryService struct {
	backend IOProvider // The IO provider to read/write the backend data.
	c       chan interface{}
}

// NewInMemoryService provides a new authentication service that keeps all accounts in memory.
// loadTimeout is the time until a load from backend must succeed (during which modifications via api are blocked).
func NewInMemoryService(backend IOProvider, loadTimeout time.Duration) *InMemoryService {
	service := &InMemoryService{
		backend: backend,
		c:       make(chan interface{}, 10),
	}
	go service.runner(loadTimeout)
	return service
}

type msgAuthenticate struct {
	username, password string
	r                  chan error
}

type msgDelete struct {
	username string
	r        chan error
}

type msgAdd struct {
	username, password string
	r                  chan error
}

type msgModify struct {
	username, password string
	r                  chan error
}

type msgVerifyModify struct {
	username, oldpassword, newpassword string
	r                                  chan error
}

type msgStartLoad struct{}

type msgLoad struct {
	username     string
	passwordHash []byte
	r            chan error
}

type msgCommit struct{}

type msgRollback struct {
	txid int64
}

type msgGetCost struct {
	r chan int
}

type msgSetCost struct {
	cost int
}

type msgList struct {
	r chan []Entry
}

func (service *InMemoryService) runner(loadTimeout time.Duration) {
	var cost int
	var inLoad bool
	var loadData *authData
	var txid int64

	curData := newAuthData()
	msgBuffer := MsgBuffer(service.c, loadTimeout)
	cost = bcrypt.DefaultCost
	for m := range service.c {
		switch e := m.(type) {
		case msgAuthenticate:
			curData.authenticate(e, cost)
		case msgDelete:
			if inLoad {
				msgBuffer <- m
			}
			curData.delete(e)
		case msgAdd:
			if inLoad {
				msgBuffer <- m
			}
			curData.add(e, cost)
		case msgModify:
			if inLoad {
				msgBuffer <- m
			}
			curData.modify(e, cost)
		case msgVerifyModify:
			if inLoad {
				msgBuffer <- m
			}
			curData.verifyModify(e, cost)
		case msgStartLoad:
			inLoad = true
			loadData = newAuthData()
			txid = time.Now().UnixNano()
			time.AfterFunc(loadTimeout, func() { // Initialize automatic rollback call. Old Rollbacks are ineffective since they have a wrong txid
				service.c <- msgRollback{txid: txid}
			})
		case msgRollback:
			if inLoad && (e.txid == 0 || (e.txid == txid && txid != 0)) {
				inLoad = false
				loadData = nil
				txid = 0
			}
		case msgCommit:
			if inLoad {
				curData = loadData
				inLoad = false
				txid = 0
			}
		case msgLoad:
			if inLoad {
				loadData.data[e.username] = e.passwordHash
				e.r <- nil
			} else {
				e.r <- ErrNoTransaction
			}
		case msgGetCost:
			e.r <- cost
		case msgSetCost:
			cost = e.cost
		case msgList:
			ret := make([]Entry, 0, len(curData.data))
			for user, passHash := range curData.data {
				ret = append(ret, Entry{Username: user, PasswordHash: passHash})
			}
			e.r <- ret
		default:
			panic("Unimplemented!")
		}
	}
	close(msgBuffer)
}

// Authenticate checks if a username is present and the password matches. Returns nil on success.
func (service *InMemoryService) Authenticate(username, password string) error {
	r := make(chan error, 1)
	service.c <- msgAuthenticate{
		username: username,
		password: password,
		r:        r,
	}
	e := <-r
	close(r)
	return e
}

// Delete a user, return nil on success.
func (service *InMemoryService) Delete(username string) error {
	r := make(chan error, 1)
	service.c <- msgDelete{
		username: username,
		r:        r,
	}
	e := <-r
	close(r)
	return e
}

// Add a user with password. Return nil on success.
func (service *InMemoryService) Add(username, password string) error {
	r := make(chan error, 1)
	service.c <- msgAdd{
		username: username,
		password: password,
		r:        r,
	}
	e := <-r
	close(r)
	return e
}

// Modify a user to use a new password. Return nil on success.
func (service *InMemoryService) Modify(username, password string) error {
	r := make(chan error, 1)
	service.c <- msgModify{
		username: username,
		password: password,
		r:        r,
	}
	e := <-r
	close(r)
	return e
}

// VerifyModify modifies the password of a user only after verifying that the old password is correct.
func (service *InMemoryService) VerifyModify(username, oldpassword, newpassword string) error {
	r := make(chan error, 1)
	service.c <- msgVerifyModify{
		username:    username,
		oldpassword: oldpassword,
		newpassword: newpassword,
		r:           r,
	}
	e := <-r
	close(r)
	return e
}

// StartLoad starts a new loading transaction. Only one loading transaction can exist at any time.
// If the loading transaction times out before the Commit() call, loaded data is lost.
// During a load transactions all modifying calls will be delayed, while Authentication calls operate
// on the old data.
// Calling StartLoad silently rolls back any previous uncommitted load transaction!
func (service *InMemoryService) StartLoad() {
	service.c <- msgStartLoad{}
}

// Load a user with a password hash. It requires a transaction started with StartLoad which needs to be
// committed with Commit.
func (service *InMemoryService) Load(username string, passwordHash []byte) error {
	r := make(chan error, 1)
	service.c <- msgLoad{
		username:     username,
		passwordHash: passwordHash,
		r:            r,
	}
	err := <-r
	close(r)
	return err
}

// Rollback current load transaction, if there is any.
func (service *InMemoryService) Rollback() {
	service.c <- msgRollback{}
}

// Commit newly loaded data as the authoritative data.
func (service *InMemoryService) Commit() {
	service.c <- msgCommit{}
}

// SetCost updates the bcrypt cost that is required.
func (service *InMemoryService) SetCost(cost int) {
	service.c <- msgSetCost{
		cost: cost,
	}
}

// GetCost returns the current target bcrypt cost of the system.
func (service *InMemoryService) GetCost() int {
	r := make(chan int, 1)
	service.c <- msgGetCost{r: r}
	c := <-r
	close(r)
	return c
}

// List all entries of the service. There is no defined order.
func (service *InMemoryService) List() []Entry {
	r := make(chan []Entry, 1)
	service.c <- msgList{r: r}
	ret := <-r
	return ret
}

// Update triggers the authentication service to request a reload from the backend storage.
func (service *InMemoryService) Update() {
	service.backend.RequestRead(service)
}

// Sync the backend.
func (service *InMemoryService) Sync() {
	service.backend.RequestWrite(service)
}

// Shutdown the authentication service, updating the backend.
func (service *InMemoryService) Shutdown() {
	service.backend.RequestWrite(service)
	service.Kill()
}

// Kill the authentication service.
func (service *InMemoryService) Kill() {
	close(service.c)
	old := service
	go func() {
		time.Sleep(time.Second * 2)
		old.c = nil
	}()
}
