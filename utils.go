package pepper

import (
	"os"
	"os/user"
	"runtime"
)

// GetHomeDir returns the home dir of the current user
// as user.Current is not implemented on darwin/amd64
// we must find a workaround...
func GetHomeDir() (string, error) {
	if runtime.GOOS == "darwin" {
		return os.Getenv("HOME"), nil
	} else {
		u, err := user.Current()
		if err != nil {
			return "", err
		}
		return u.HomeDir, nil
	}
}
