package keyutils

import (
	"testing"
)

func TestReadAndAddKey(t *testing.T) {
	k, err := AddKey(USER, "testkey", "hello this is new data", KEY_SPEC_USER_KEYRING)
	t.Log("key is", k)
	if err != nil {
		t.Fatal("error adding key", err)
	} else {

		result, err := ReadKey(k)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("decrypted is", result)
		if result != "hello this is new data" {
			t.Fatal("mismatched result and data", result)
		}
	}
}

func TestRequestKey(t *testing.T) {
	k, err := AddKey(USER, "testkey", "hello this is new data", KEY_SPEC_USER_KEYRING)
	t.Log("key is", k)
	if err != nil {
		t.Fatal("error adding key", err)
	} else {

		result, err := RequestKey(USER, "testkey", KEY_SPEC_USER_KEYRING)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("read key is", result)
		if result != k {
			t.Fatal("mismatched key", result)
		}
	}
}

func TestClearKey(t *testing.T) {

	TestRequestKey(t)
	err := Clear(KEY_SPEC_USER_KEYRING)

	if err != nil {
		t.Fatal(err)
	}
	result, err := RequestKey(USER, "testkey", KEY_SPEC_USER_KEYRING)
	t.Log("read key is", result)
	if result != 0 {
		t.Fatal("mismatched key", result)
	}

}
