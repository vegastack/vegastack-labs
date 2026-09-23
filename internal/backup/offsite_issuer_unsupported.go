//go:build !linux

package backup

import (
	"errors"
	"os"
)

func SealedBearerFile([]byte) (*os.File, error) {
	return nil, errors.New("offsite bearer requires linux sealed memory")
}
