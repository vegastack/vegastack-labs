//go:build windows

package clientprofile

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

const windowsDirectoryDeleteChild windows.ACCESS_MASK = 0x00000040

type windowsAccess struct {
	sid  string
	mask windows.ACCESS_MASK
}

type windowsPathKind uint8

const (
	windowsPrivateFile windowsPathKind = iota
	windowsExecutable
	windowsDirectory
)

func trustedFile(path string, info os.FileInfo) bool {
	return trustedWindowsPath(path, info, windowsPrivateFile)
}

func trustedExecutable(path string, info os.FileInfo) bool {
	return trustedWindowsPath(path, info, windowsExecutable)
}

func trustedDirectory(path string, info os.FileInfo) bool {
	return trustedWindowsPath(path, info, windowsDirectory)
}

func trustedWindowsPath(path string, expected os.FileInfo, kind windowsPathKind) bool {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	flags := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if kind == windowsDirectory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return false
	}
	file := os.NewFile(uintptr(handle), "trusted-client-profile-file")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return false
	}
	defer file.Close()
	var metadata windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &metadata) != nil || !windowsPathMetadataTrusted(metadata.FileAttributes, metadata.NumberOfLinks, kind) {
		return false
	}
	currentInfo, err := file.Stat()
	if err != nil || !os.SameFile(expected, currentInfo) {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	entries := make([]windowsAccess, 0, dacl.AceCount)
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, index, &ace) != nil || ace == nil {
			return false
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.String() == "" {
			return false
		}
		entries = append(entries, windowsAccess{sid: sid.String(), mask: ace.Mask})
	}
	return windowsPathACLTrusted(owner.String(), user.User.Sid.String(), entries, kind)
}

func windowsFileMetadataTrusted(attributes, links uint32) bool {
	return windowsPathMetadataTrusted(attributes, links, windowsPrivateFile)
}

func windowsPathMetadataTrusted(attributes, links uint32, kind windowsPathKind) bool {
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if kind == windowsDirectory {
		return attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 && links >= 1
	}
	return attributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && links == 1
}

func windowsACLTrusted(owner, current string, entries []windowsAccess, executable bool) bool {
	kind := windowsPrivateFile
	if executable {
		kind = windowsExecutable
	}
	return windowsPathACLTrusted(owner, current, entries, kind)
}

func windowsDirectoryACLTrusted(owner, current string, entries []windowsAccess) bool {
	return windowsPathACLTrusted(owner, current, entries, windowsDirectory)
}

func windowsPathACLTrusted(owner, current string, entries []windowsAccess, kind windowsPathKind) bool {
	if owner == "" || current == "" {
		return false
	}
	privileged := map[string]bool{
		current:             true,
		"S-1-5-18":          true,
		"S-1-5-32-544":      true,
		trustedInstallerSID: true,
	}
	if kind == windowsExecutable || kind == windowsDirectory {
		if !privileged[owner] {
			return false
		}
	} else if owner != current {
		return false
	}
	unsafeExecutable := windows.ACCESS_MASK(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	unsafeDirectory := windows.ACCESS_MASK(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windowsDirectoryDeleteChild | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	for _, entry := range entries {
		if entry.sid == "" || entry.mask == 0 {
			continue
		}
		if kind == windowsPrivateFile && !privileged[entry.sid] {
			return false
		}
		if kind == windowsExecutable && !privileged[entry.sid] && entry.mask&unsafeExecutable != 0 {
			return false
		}
		if kind == windowsDirectory && !privileged[entry.sid] && entry.mask&unsafeDirectory != 0 {
			return false
		}
	}
	return true
}
