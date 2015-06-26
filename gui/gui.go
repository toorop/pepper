package main

import (
	"io"
	"log"
	"net/http"
	"time"

	"github.com/GeertJohan/go.rice"
	"github.com/codegangsta/negroni"
	"github.com/julienschmidt/httprouter"
	"github.com/nbio/httpcontext"
	"github.com/pkg/browser"
)

const (
	// Max size of the posted body
	body_read_limit = 1048576
)

var assets http.FileSystem

// LaunchServer launches HTTP server
func main() {
	router := httprouter.New()
	router.HandlerFunc("GET", "/ping", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("pong"))
	})

	// prod (tag dev is not present)
	if assets == nil {
		// rices boxes
		httpbox := rice.MustFindBox("../assets/http")
		assets = httpbox.HTTPBox()
	}

	// assets
	router.Handler("GET", "/assets/*res", http.StripPrefix("/assets/", http.FileServer(assets)))

	// index
	router.HandlerFunc("GET", "/", handlerIndex)

	// http server
	n := negroni.New(negroni.NewRecovery())
	n.UseHandler(router)
	select {
	case <-time.After(1 * time.Second):
		browser.OpenURL("http://127.0.0.1:6480/")
	}
	log.Println("GUI HTTP server will be lanched on http://127.0.0.1:6480")
	log.Fatalln(http.ListenAndServe("0.0.0.0:6480", n))
	// launch browser

}

// wrapHandler puts httprouter.Params in query context
// in order to keep compatibily with http.Handler
func wrapHandler(h func(http.ResponseWriter, *http.Request)) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		httpcontext.Set(r, "params", ps)
		h(w, r)
	}
}

func handlerIndex(w http.ResponseWriter, req *http.Request) {
	file, err := assets.Open("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, file)
}
