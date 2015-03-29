//
// keyutils provides libkeyutils bindings for Go.
//
// To build, it requires libkeyutils binaries and headers, e.g..
// apt-get install libkeyutils-dev
//
package keyutils

/*
#cgo linux LDFLAGS: -lkeyutils

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <keyutils.h>
*/
import "C"
import (
	"syscall"
	"unsafe"
)

type KeySerial int
type KeyType string

const (
	USER    KeyType = "user"
	KEYRING KeyType = "keyring"
)

const (
	KEY_SPEC_THREAD_KEYRING       KeySerial = KeySerial(C.KEY_SPEC_THREAD_KEYRING)
	KEY_SPEC_USER_KEYRING                   = KeySerial(C.KEY_SPEC_USER_KEYRING)
	KEY_SPEC_PROCESS_KEYRING                = KeySerial(C.KEY_SPEC_PROCESS_KEYRING)
	KEY_SPEC_SESSION_KEYRING                = KeySerial(C.KEY_SPEC_SESSION_KEYRING)
	KEY_SPEC_USER_SESSION_KEYRING           = KeySerial(C.KEY_SPEC_USER_SESSION_KEYRING)
)

//
// RequestKey() wraps request_key(2).
//
// It returns the serial number of the key found with type = `keyType`
// and description = `desc` in the keyring `keyring`.
//
func RequestKey(keyType KeyType, desc string, keyring KeySerial) (KeySerial, error) {
	result, err := C.request_key(
		C.CString(string(keyType)),
		C.CString(desc),
		nil,
		C.key_serial_t(int(keyring)))

	if err != nil {
		return 0, err.(syscall.Errno)
	} else {
		return KeySerial(int(result)), nil
	}
}

//
// AddKeyBytes wraps add_key(2).
//
// It returns the serial number of the added key.
//
func AddKeyBytes(keyType KeyType, desc string, data []byte, keyring KeySerial) (KeySerial, error) {
	payloadLen := C.size_t(len(data))
	result, err := C.add_key(C.CString(string(keyType)), C.CString(desc), unsafe.Pointer(&data[0]), payloadLen, C.key_serial_t(int(keyring)))

	if err != nil {
		return 0, err.(syscall.Errno)
	} else {
		return KeySerial(int(result)), nil
	}
}

//
// AddKey is a helper for AddKeyBytes() that accepts a data string instead of
// a byte array.
//
func AddKey(keyType KeyType, desc string, data string, keyring KeySerial) (KeySerial, error) {
	bytes := []byte(data)

	return AddKeyBytes(keyType, desc, bytes, keyring)
}

//
// ReadKey() reads a key with the given serial # using keyctl_read_alloc(3), and returns the bytes read.
//
func ReadKeyBytes(key KeySerial) ([]byte, error) {

	var ptr unsafe.Pointer = nil
	bytes, err := C.keyctl_read_alloc(C.key_serial_t(int(key)), (*unsafe.Pointer)(&ptr))

	if err == nil && bytes > 0 && ptr != nil {
		result := C.GoBytes(ptr, bytes)
		C.free(ptr)
		return result, nil
	}

	return nil, err.(syscall.Errno)
}

//
// ReadKey() is a wrapper for ReadKeyBytes() that reads a key with the given serial #, and convert to a string value.
//
func ReadKey(key KeySerial) (string, error) {
	bytes, err := ReadKeyBytes(key)

	if err != nil {
		return "", err
	} else {
		return string(bytes), nil
	}
}

//
// Clear() will call keyctl_clear(3) to clear a keyring.
//
func Clear(keyring KeySerial) error {
	_, err := C.keyctl_clear(C.key_serial_t(keyring))

	if err != nil {
		return err.(syscall.Errno)
	}
	return nil
}

//
// Chown wraps keyctl_chown(3) to change ownership of the key.
//
func Chown(key KeySerial, uid C.uid_t, gid C.gid_t) error {
	_, err := C.keyctl_chown(C.key_serial_t(key), uid, gid)

	if err != nil {
		return err.(syscall.Errno)
	}
	return nil
}

//
// Revoke() will call keyctl_revoke(3) to revoke a key.
//
func Revoke(key KeySerial) error {
	_, err := C.keyctl_revoke(C.key_serial_t(key))

	if err != nil {
		return err.(syscall.Errno)
	}
	return nil
}

//
// SetTimeout() will call keyctl_set_timeout(3) to set a `seconds`
// timeout on a key
//
func SetTimeout(key KeySerial, seconds uint) error {
	_, err := C.keyctl_set_timeout(C.key_serial_t(key), C.uint(seconds))

	if err != nil {
		return err.(syscall.Errno)
	}
	return nil
}
