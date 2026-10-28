package main

import (
	"crypto/tls"
	"fmt"
)

func main() {
	fixture := &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- intentional offline scanner fixture
	fmt.Println(fixture.MinVersion)
}
