//go:build windows

package clientfile

import (
	"context"
	"os"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/sys/windows"
)

func readPlatform(ctx context.Context, path string, maximum int64) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	file := os.NewFile(uintptr(handle), "inventory-file")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	defer file.Close()
	var before, after windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &before) != nil || before.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || before.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || before.NumberOfLinks != 1 || fileSize(before) < 1 || fileSize(before) > maximum {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	content, err := readBounded(ctx, file, maximum)
	if err != nil {
		return nil, err
	}
	if windows.GetFileInformationByHandle(handle, &after) != nil || before.VolumeSerialNumber != after.VolumeSerialNumber || before.FileIndexHigh != after.FileIndexHigh || before.FileIndexLow != after.FileIndexLow || fileSize(before) != fileSize(after) || before.NumberOfLinks != after.NumberOfLinks || int64(len(content)) != fileSize(after) {
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	currentHandle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	defer windows.CloseHandle(currentHandle)
	var current windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(currentHandle, &current) != nil || current.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || current.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || after.VolumeSerialNumber != current.VolumeSerialNumber || after.FileIndexHigh != current.FileIndexHigh || after.FileIndexLow != current.FileIndexLow || fileSize(after) != fileSize(current) || after.NumberOfLinks != current.NumberOfLinks {
		return nil, readError(generated.ErrorCodeIntegrityFailure)
	}
	return content, nil
}

func fileSize(info windows.ByHandleFileInformation) int64 {
	return int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
}
