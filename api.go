// Package authfile implements a library and provider for simple password management.
// It handles files that contain lines of username/password and provides an API to create, verify, update and delete entries.
// username:hashed_password
// Lines starting with # are ignored.
// Lines starting with $ set the cost of the bcrypt. otherwise the default cost of the bcrypt implementation is used.
// Service. Reader/writer
package authfile

// IAuthenticationService is the interface of an authentication service
type IAuthenticationService interface {
	// Authenticate checks if a username is present and the password matches. Returns nil on success.
	Authenticate(username, password string) error
	// Delete a user, return nil on success.
	Delete(username string) error
	// Add a user with password. Return nil on success.
	Add(username, password string) error
	// Modify a user to use a new password. Return nil on success.
	Modify(username, password string) error
	// VerifyModify modifies the password of a user only after verifying that the old password is correct.
	VerifyModify(username, oldpassword, newpassword string) error
	// StartLoad creates a new loading transaction.
	StartLoad()
	// Load a user with a password hash.
	Load(username string, passwordHash []byte) error
	// Commit newly loaded data as the authoritative data.
	Commit()
	// Rollback a current load transaction.
	Rollback()
	// SetCost updates the bcrypt cost that is required.
	SetCost(cost int)
	// GetCost returns the current target bcrypt cost of the system.
	GetCost() int
	// List all entries of the service. There is no defined order.
	List() []Entry
	// Update triggers the authentication service to request a reload from the backend storage.
	Update()
	// Sync the backend.
	Sync()
	// Shutdown the authentication service, updating the backend.
	Shutdown()
	// Kill the authentication service.
	Kill()
}

// IOProvider implements reading/writing services for the authentication service.
// The authentication service requests reads/writes, and the IOProvider is expected
// to use the API to get the serialized data from the provider or push serialized data
// to the provider.
type IOProvider interface {
	RequestRead(authservice IAuthenticationService)  // Called when the auth provider wants to read the backend data.
	RequestWrite(authservice IAuthenticationService) // Called when the auth provider wants to write to the backend.
	UsernameIsValid(username string) bool            // Returns true if the username is safe, false if not.
}

// Entry defines a single entry.
type Entry struct {
	Username     string // The username.
	PasswordHash []byte // The password hash.
}
