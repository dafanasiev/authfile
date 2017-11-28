package authfile

import (
	"testing"
	"time"
)

func Test_Short(t *testing.T) {
	fb, err := NewFileBackend("/tmp/authfile.test", 0600, time.Second*5)
	if err != nil {
		t.Fatalf("NewFileBackend: %s", err)
	}
	authProvider := NewInMemoryService(fb, time.Second)
	authProvider.SetCost(13)
	if err := authProvider.Add("test", "testPass"); err != nil {
		t.Errorf("Add: %s", err)
	}
	if err := authProvider.Authenticate("test", "testPass"); err != nil {
		t.Errorf("Authenticate: %s", err)
	}
	if err := authProvider.Authenticate("test", "testPassWrong"); err == nil {
		t.Errorf("Authenticate did not throw error when using wrong password")
	}
	authProvider.Sync()
	time.Sleep(time.Second)
}
