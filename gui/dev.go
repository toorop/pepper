// +build !prod

package main

import "net/http"

func init() {
	assets = http.Dir("../assets/http")
}
