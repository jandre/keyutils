# What is this?

Go bindings for Linux's libkeyutils. libkeyutils provides an interface to the Linux kernel's 
keyring APIs, useful for storing secrets.

It requires headers and libs for libkeyutils to be installed, e.g. apt-get install libkeyutils-dev.

# How to build and install

```bash
sudo apt-get install -y libkeyutils-dev # on ubuntu
go get github.com/jandre/keyutils
````

# How to use

See example/main.go to see an example of adding and reading a 
key from the user keyring.

```go
package main

import (
	"log"

	"github.com/jandre/keyutils"
)

func main() {
	id, err := keyutils.AddKey(keyutils.USER, "test123", "hello", keyutils.KEY_SPEC_USER_KEYRING)

	if err != nil {
		log.Fatal("Error adding key:", err)
	}
	log.Println("Added key test123 with serial:", id)
	val, err := keyutils.ReadKey(id)

	if err != nil {
		log.Fatal("Error reading key:", err)
	}

	log.Println("Read:", val)
```

```bash
$ go run example/main.go
2015/03/29 17:20:36 Added key test123 with serial: 222717072
2015/03/29 17:20:36 Read: hello
```

# TODO
Many of the `keyctl_*` apis are not yet supported.
