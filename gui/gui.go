package main

import (
	"log"
	"net/http"
	"os/user"

	"github.com/GeertJohan/go.rice"
	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"
	"github.com/nbio/httpcontext"
)

const (
	// Max size of the posted body
	body_read_limit = 1048576
)

// LaunchServer launches HTTP server
func launchGui() {
	router := httprouter.New()
	router.HandlerFunc("GET", "/ping", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("pong"))
	})

	// rices boxes
	httpbox := rice.MustFindBox("assets/http")
	router.Handler("GET", "/assets/*res", http.StripPrefix("/assets/", http.FileServer(httpbox.HTTPBox())))

	// http server
	n := negroni.New(negroni.NewRecovery())
	n.UseHandler(router)
	log.Println("GUI HTTP server lanched on http://127.0.0.1:6480")
	log.Fatalln(http.ListenAndServe("0.0.0.0:6480", n))
}

// wrapHandler puts httprouter.Params in query context
// in order to keep compatibily with http.Handler
func wrapHandler(h func(http.ResponseWriter, *http.Request)) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		httpcontext.Set(r, "params", ps)
		h(w, r)
	}
}
