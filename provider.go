package authfile

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Default provider implementation

// FileBackend implements a file based backend.
type FileBackend struct {
	handle      *os.File
	authservice IAuthenticationService
	lastHash    []byte      // hash of the file inode at least check
	mutex       *sync.Mutex // mutex protecting the structure.
}

// NewFileBackend returns a new file based IO backend. The backend will also start
// a file change monitor if the update parameter is >0. In this case the authservice
// update function will be called if the file has changed.
func NewFileBackend(filename string, perm os.FileMode, update time.Duration) (*FileBackend, error) {
	return newFileBackend(filename, os.O_RDWR|os.O_CREATE, perm, update)
}

// NewROFileBackend returns a new Read-Only file based IO backend. The backend will also start
// a file change monitor if the update parameter is >0. In this case the authservice
// update function will be called if the file has changed.
func NewROFileBackend(filename string, perm os.FileMode, update time.Duration) (*FileBackend, error) {
	return newFileBackend(filename, os.O_RDONLY, perm, update)
}

func newFileBackend(filename string, flag int, perm os.FileMode, update time.Duration) (*FileBackend, error) {
	f, err := os.OpenFile(filename, flag, perm)
	if err != nil {
		return nil, err
	}
	fb := &FileBackend{
		handle: f,
		mutex:  new(sync.Mutex),
	}
	if update > 0 {
		go fb.updateCheck(update)
	}
	return fb, nil
}

// UsernameIsValid checks if a username is valid. It may not start with "$"" or "#", and may not contain a ":".
func (filebackend FileBackend) UsernameIsValid(username string) bool {
	l := strings.TrimSpace(username)
	if l[0] == '$' || l[0] == '#' {
		return false
	}
	if strings.Index(l, ":") != -1 {
		return false
	}
	return true
}

// Close the backend file.
func (filebackend *FileBackend) Close() {
	filebackend.mutex.Lock()
	defer filebackend.mutex.Unlock()
	if filebackend.handle != nil {
		filebackend.handle.Close()
		filebackend.handle = nil
	}
}

// updateCheck goroutine. The inner loop (timed) continues until the backend file handle is nil.
func (filebackend *FileBackend) updateCheck(update time.Duration) {
	t := time.NewTicker(update)
	for range t.C {
		if !filebackend.updateCheckInner() {
			t.Stop()
			return
		}
	}
}

// updateCheckInner tests if the inode hash has changed, if yes it triggers an update of the authentication service. It returns
// false in case of error (like if the file handle has gone away) which stops the update check loop.
func (filebackend *FileBackend) updateCheckInner() bool {
	filebackend.mutex.Lock()
	defer filebackend.mutex.Unlock()
	if filebackend.authservice == nil {
		return true
	}
	if filebackend.handle == nil {
		return false
	}
	nhash, err := filebackend.getChangeStamp()
	if err != nil {
		return false
	}
	if !bytes.Equal(nhash, filebackend.lastHash) {
		filebackend.lastHash = nhash
		go filebackend.authservice.Update()
	}
	return true
}

// getChangeStamp returns a byteslice that changes when the file has been touched for modification.
func (filebackend *FileBackend) getChangeStamp() ([]byte, error) {
	var inode uint64
	stat, err := filebackend.handle.Stat()
	if err != nil {
		return nil, err
	}
	sysStat := stat.Sys()
	if nt, ok := sysStat.(*syscall.Stat_t); ok {
		inode = uint64(nt.Ino)
	}
	return []byte(fmt.Sprintf("%d.%d", inode, stat.ModTime().UnixNano())), nil
}

// RequestRead is called by the authentication service when it requests a read.
func (filebackend *FileBackend) RequestRead(authservice IAuthenticationService) {
	// Go through the lines, call cost/modify
	filebackend.mutex.Lock()
	defer filebackend.mutex.Unlock()
	if filebackend.authservice == nil {
		filebackend.authservice = authservice
	}
	filebackend.lastHash, _ = filebackend.getChangeStamp() // preempt the update timer.
	go filebackend.readFile()
}

func (filebackend *FileBackend) readFile() {
	var line, lineTrimmed string
	var err error
	filebackend.mutex.Lock()
	defer filebackend.mutex.Unlock()
	filebackend.handle.Seek(0, 0) // Point to beginning of file
	r := bufio.NewReader(filebackend.handle)
	filebackend.authservice.StartLoad()
	for {
		line, err = r.ReadString('\n')
		if err == io.EOF {
			break
		}
		lineTrimmed = strings.TrimSpace(line)
		if len(lineTrimmed) < 2 { // Ignore empty or single char lines.
			continue
		}
		if lineTrimmed[0] == '#' { // Ignore comments.
			continue
		}
		if lineTrimmed[0] == '$' { // Set cost.
			cost, err := strconv.Atoi(lineTrimmed[1:])
			if err != nil { // We ignore lines with bad cost parameter.
				continue
			}
			filebackend.authservice.SetCost(cost)
		}
		fields := strings.Split(lineTrimmed, ":")
		if len(fields) != 2 { // Skip lines that have the wrong format
			continue
		}
		filebackend.authservice.Load(fields[0], []byte(fields[1]))
	}
	filebackend.authservice.Commit()
}

// RequestWrite is called by the authentication service when it requests a write.
func (filebackend *FileBackend) RequestWrite(authservice IAuthenticationService) {
	// Request list, format and write
	filebackend.mutex.Lock()
	defer filebackend.mutex.Unlock()
	if filebackend.authservice == nil {
		filebackend.authservice = authservice
	}
	go filebackend.writeFile()
}

func (filebackend *FileBackend) writeFile() {
	filebackend.mutex.Lock()
	defer filebackend.mutex.Unlock()
	defer func() {
		filebackend.lastHash, _ = filebackend.getChangeStamp() // preempt the update timer.
	}()
	filebackend.handle.Truncate(0)
	filebackend.handle.Seek(0, 0) // Point to beginning of file
	w := bufio.NewWriter(filebackend.handle)
	defer w.Flush()
	w.WriteString("$" + strconv.Itoa(filebackend.authservice.GetCost()) + "\n") // Save cost parameter.
	entries := filebackend.authservice.List()
	for _, e := range entries {
		w.WriteString(e.Username + ":" + string(e.PasswordHash) + "\n")
	}
}
