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
	t.Log("Clear() read key is", result)
	if result != 0 {
		t.Fatal("found a key that should have been cleared", result)
	}

}

func TestDescribeKey(t *testing.T) {

	k, err := AddKey(USER, "testkey", "hello this is new data", KEY_SPEC_USER_KEYRING)
	t.Log("key is", k)

	if err != nil {
		t.Fatal("error adding key", err)
	}
	result, err := DescribeKey(k)

	if err != nil {
		t.Fatal("error describing key", err)
	}

	if result == nil {
		t.Fatal("expected a result from DescribeKey, and got nothing")
	}

	t.Log("result is", result)

	if result.Description != "testkey" {
		t.Fatal("bad result", result)
	}

}
