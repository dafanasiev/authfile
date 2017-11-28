// bcryptfile is a tool to edit bcrypt password files.
// -i <file> <cost>					:Init a file <file> with <cost>
// -a <file> <username> [password]	:Add user <username> with password [password]. If [password] is not given, ask for it.
// -d <file> <username>				:Delete username
// -m <file> <username> [password]	:Modify password of user <username> to [password]. If [password] is not given, ask for it.
// -C <file> <cost>					:Change cost in file.
// -h | --help						:Show help
// Major hack written while tired.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/JonathanLogan/authfile"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

var help = `%s%s is a tool to edit bcrypt password files.
-i <file> <cost>                :Init a file <file> with <cost>
-a <file> <username> [password] :Add user <username> with password [password]. 
                                :If [password] is not given, ask for it.
-d <file> <username>            :Delete username
-m <file> <username> [password] :Modify password of user <username> to [password].
                                :If [password] is not given, ask for it.
-C <file> <cost>                :Change cost in file.
-h | --help                     :Show help
`

func printHelp(e string) {
	if e != "" {
		e = e + "\n\n"
	}
	fmt.Fprintf(os.Stderr, help, e, os.Args[0])
	os.Exit(1)
}

func printError(e string) {
	if e != "" {
		fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		os.Exit(1)
	}
	os.Exit(0)
}

func openFile(filename string, perm int) (*os.File, error) {
	f, err := os.OpenFile(filename, perm, 0600)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func tempFile() (*os.File, error) {
	f, err := ioutil.TempFile(os.TempDir(), "auth")
	if err != nil {
		return nil, err
	}
	return f, nil
}

func findCost(f *os.File) (cost int) {
	cost = bcrypt.DefaultCost
	f.Seek(0, 0)
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line[0] == '$' && len(line) > 1 {
			c, err := strconv.Atoi(line[1:])
			if err != nil {
				continue
			}
			return c
		}
	}
	return
}

func askPassword(prompt string) (string, error) {
	c := make(chan os.Signal, 1)
	oldState, err := terminal.GetState(0)
	if err != nil {
		return "", err
	}
	go func() {
		for range c {
			terminal.Restore(0, oldState)
			os.Exit(1)
		}
	}()
	signal.Notify(c, os.Interrupt, os.Kill)
	defer signal.Stop(c)
	for {
		fmt.Fprintf(os.Stdout, "%s: ", prompt)
		pass1, err := terminal.ReadPassword(0)
		if err != nil {
			return "", err
		}
		pass1 = bytes.TrimSpace(pass1)
		if len(pass1) == 0 {
			fmt.Fprintln(os.Stdout, "\nNo password entered. Repeast.")
			continue
		}
		fmt.Fprintf(os.Stdout, "\n%s (again): ", prompt)
		pass2, err := terminal.ReadPassword(0)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(pass1, pass2) {
			fmt.Fprintln(os.Stdout, "\nPasswords do not match. Repeast.")
			continue
		}
		fmt.Fprintf(os.Stdout, "\n")
		return string(pass1), nil
	}

}

func initFile(args []string) error {
	if len(args) < 2 {
		printHelp("Missing arguments.")
	}
	cost, err := strconv.Atoi(args[1])
	if err != nil {
		printHelp(fmt.Sprintf("Not a number: \"%s\"", args[1]))
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		printHelp(fmt.Sprintf("Cost must be between %d and %d. Given: %d.", bcrypt.MinCost, bcrypt.MaxCost, cost))
	}
	f, err := openFile(args[0], os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Write([]byte("$" + strconv.Itoa(cost) + "\n"))
	return nil
}

func userLine(cost int, username, password string) string {
	if !(authfile.FileBackend{}).UsernameIsValid(username) {
		printHelp("Username is not valid.")
	}
	if password == "" {
		var err error
		password, err = askPassword("Enter password for user \"" + username + "\"")
		if err != nil {
			printHelp(err.Error())
		}
	}
	phash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		printHelp(err.Error())
	}
	return username + ":" + string(phash) + "\n"
}

// filterFunc reads a line in and returns a line. If lastLine is true, the last line
// has already been read.
type filterFunc func(in string, lastLine bool) (string, error)

func filter(infile, outfile *os.File, fFunc filterFunc) error {
	infile.Seek(0, 0)
	outfile.Seek(0, 0)
	r := bufio.NewReader(infile)
	w := bufio.NewWriter(outfile)
	defer w.Flush()
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			s, err2 := fFunc(line, false)
			if err2 != nil {
				return err2
			}
			_, err3 := w.WriteString(s)
			if err3 != nil {
				return err3
			}
		}
		if err != nil {
			break
		}
	}
	s, err := fFunc("", true)
	if err != nil {
		return err
	}
	_, err = w.WriteString(s)
	return err
}

func matchesUser(username, line string) bool {
	line = strings.TrimSpace(line)
	fields := strings.Split(line, ":")
	if len(fields) != 2 {
		return false
	}
	ut := strings.TrimSpace(fields[0])
	if ut == username {
		return true
	}
	return false
}

func writeChanges(in, out *os.File) error {
	in.Seek(0, 0)
	out.Truncate(0)
	out.Seek(0, 0)
	_, err := io.CopyBuffer(out, in, make([]byte, 4096))
	return err
}

func addUser(args []string) error {
	var password string
	if len(args) < 2 {
		printHelp("Missing arguments.")
	}
	username := strings.TrimSpace(args[1])
	if len(args) >= 3 {
		password = args[2]
	}
	f, err := openFile(args[0], os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	cost := findCost(f)
	t, err := tempFile()
	if err != nil {
		return err
	}
	defer func() {
		name := t.Name()
		t.Close()
		os.Remove(name)
	}()
	newline := userLine(cost, username, strings.TrimSpace(password))
	err = filter(f, t, func(in string, lastLine bool) (string, error) {
		if matchesUser(username, in) {
			return "", errors.New("Username already in file.")
		}
		if lastLine {
			return newline, nil
		}
		return in, nil
	})
	if err != nil {
		return err
	}
	if err := writeChanges(t, f); err != nil {
		return err
	}
	return nil
}

func deleteUser(args []string) error {
	username := strings.TrimSpace(args[1])
	if username == "" {
		return errors.New("No username given.")
	}
	f, err := openFile(args[0], os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := tempFile()
	if err != nil {
		return err
	}
	defer func() {
		name := t.Name()
		t.Close()
		os.Remove(name)
	}()
	found := false
	err = filter(f, t, func(in string, lastLine bool) (string, error) {
		if matchesUser(username, in) {
			found = true
			return "", nil
		}
		if lastLine && !found {
			return "", errors.New("User not found.")
		}
		return in, nil
	})
	if err != nil {
		return err
	}
	if err := writeChanges(t, f); err != nil {
		return err
	}
	return nil
}

func changeUser(args []string) error {
	var password string
	if len(args) < 2 {
		printHelp("Missing arguments.")
	}
	username := strings.TrimSpace(args[1])
	if len(args) >= 3 {
		password = args[2]
	}
	f, err := openFile(args[0], os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	cost := findCost(f)
	t, err := tempFile()
	if err != nil {
		return err
	}
	defer func() {
		name := t.Name()
		t.Close()
		os.Remove(name)
	}()
	found := false
	newline := userLine(cost, username, strings.TrimSpace(password))
	err = filter(f, t, func(in string, lastLine bool) (string, error) {
		if matchesUser(username, in) {
			found = true
			return newline, nil
		}
		if lastLine && !found {
			return "", errors.New("Username not found.")
		}
		return in, nil
	})
	if err != nil {
		return err
	}
	if err := writeChanges(t, f); err != nil {
		return err
	}
	return nil
}

func changeCost(args []string) error {
	if len(args) < 2 {
		printHelp("Missing arguments.")
	}
	cost, err := strconv.Atoi(args[1])
	if err != nil {
		printHelp(fmt.Sprintf("Not a number: \"%s\"", args[1]))
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		printHelp(fmt.Sprintf("Cost must be between %d and %d. Given: %d.", bcrypt.MinCost, bcrypt.MaxCost, cost))
	}
	f, err := openFile(args[0], os.O_RDWR)
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := tempFile()
	if err != nil {
		return err
	}
	defer func() {
		name := t.Name()
		t.Close()
		os.Remove(name)
	}()
	found := false
	newline := "$" + strconv.Itoa(cost) + "\n"
	err = filter(f, t, func(in string, lastLine bool) (string, error) {
		ix := strings.TrimSpace(in)
		if len(ix) > 0 && ix[0] == '$' {
			found = true
			return newline, nil
		}
		if lastLine && !found {
			return newline, nil
		}
		return in, nil
	})
	if err != nil {
		return err
	}
	if err := writeChanges(t, f); err != nil {
		return err
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printHelp("")
	}
	switch os.Args[1] {
	case "-h", "--help":
		printHelp("")
	case "-i":
		if err := initFile(os.Args[2:]); err != nil {
			printError(err.Error())
		}
	case "-a":
		if err := addUser(os.Args[2:]); err != nil {
			printError(err.Error())
		}
	case "-d":
		if err := deleteUser(os.Args[2:]); err != nil {
			printError(err.Error())
		}
	case "-m":
		if err := changeUser(os.Args[2:]); err != nil {
			printError(err.Error())
		}
	case "-C":
		if err := changeCost(os.Args[2:]); err != nil {
			printError(err.Error())
		}
	default:
		printHelp(fmt.Sprintf("Unknown command \"%s\".", os.Args[1]))
	}
}
