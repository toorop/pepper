package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/GeertJohan/go.rice"
	"github.com/codegangsta/cli"
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
	app := cli.NewApp()
	app.Name = "pepper gui"
	app.Usage = "User interface for pepper"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "ip",
			Value: "127.0.0.1",
			Usage: "IP to bind",
		},
		cli.IntFlag{
			Name:  "port",
			Value: 6480,
			Usage: "port to bind",
		},
	}
	app.Action = func(c *cli.Context) {
		router := httprouter.New()
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
		httpAddr := c.String("ip") + ":" + strconv.FormatInt(int64(c.Int("port")), 10)
		browserAddr := httpAddr
		if c.String("ip") == "0.0.0.0" {
			browserAddr = "127.0.0.1:" + strconv.FormatInt(int64(c.Int("port")), 10)
		}

		n := negroni.New(negroni.NewRecovery())
		n.UseHandler(router)
		select {
		case <-time.After(1 * time.Second):
			browser.OpenURL(browserAddr)
		}
		log.Println("GUI HTTP server listening on " + httpAddr)
		log.Fatalln(http.ListenAndServe(httpAddr, n))
	}

	app.Run(os.Args)

}

// wrapHandler puts httprouter.Params in query context
// in order to keep compatibily with http.Handler
func wrapHandler(h func(http.ResponseWriter, *http.Request)) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		httpcontext.Set(r, "params", ps)
		h(w, r)
	}
}

// handlerIndex serves /
func handlerIndex(w http.ResponseWriter, req *http.Request) {
	file, err := assets.Open("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Copy(w, file)
}
