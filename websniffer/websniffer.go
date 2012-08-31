package main

import (
	"bytes"
	"code.google.com/p/go.net/websocket"
	"code.google.com/p/gorilla/mux"
	"flag"
	"os"
	//	  "github.com/mrlauer/sniffer/sniffer"
	"html/template"
	"log"
	"net/http"
	"os/exec"
	"path"
	"runtime"
	"time"
)

var StaticDir string
var TemplateDir string

func init() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("Could not get file")
	}
	StaticDir = path.Join(path.Dir(file), "static")
	TemplateDir = path.Join(path.Dir(file), "templates")
}

func coffeeHandler(w http.ResponseWriter, req *http.Request) {
	filename := mux.Vars(req)["filename"]
	w.Header().Set("Cache-Control", "no-cache")
	filepath := path.Join(StaticDir, filename)

	stat, err := os.Stat(filepath)
	if err != nil {
		http.NotFound(w, req)
		return
	}
	// We may not have to do anything if the file hasn't changed. Taken from http package.
	mod := stat.ModTime()
	if !mod.IsZero() {
		t, err := time.Parse(http.TimeFormat, req.Header.Get("If-Modified-Since"))
		if err == nil && mod.Before(t.Add(1*time.Second)) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	w.Header().Set("Content-type", "application/javascript")
	cmd := exec.Command("coffee", "-p", filepath)
	buffer := bytes.NewBuffer(nil)
	cmd.Stdout = buffer
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Print(err)
		http.Error(w, http.StatusText(500), 500)
		return
	}
	http.ServeContent(w, req, filename+".js", mod, bytes.NewReader(buffer.Bytes()))
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	filename := mux.Vars(r)["filename"]
	w.Header().Set("Cache-Control", "no-cache")
	filepath := path.Join(StaticDir, filename)
	if stat, err := os.Stat(filepath); err != nil || stat.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath)
}

func wsockHandler(ws *websocket.Conn) {
	data := map[string]interface{}{
		"id":         1,
		"fromClient": true,
		"header":     "This is the header\nOhai!",
		"body":       "This is the body\nbody body body",
	}
	err := websocket.JSON.Send(ws, data)
	if err != nil {
		log.Println(err.Error())
	}
	time.Sleep(time.Second * 5)
	data = map[string]interface{} {
		"error": "Oh poo.",
	}
	err = websocket.JSON.Send(ws, data)
	if err != nil {
		log.Println(err.Error())
	}
	time.Sleep(time.Second * 5)
	ws.Close()
}

func index(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles(path.Join(TemplateDir, "websniffer.html")))
	err := t.Execute(w, nil)
	if err != nil {
		log.Println(err)
	}
}

func main() {
	addr := flag.String("addr", ":8080", "address of the sniffer web interface")
	flag.Parse()

	r := mux.NewRouter()
	r.HandleFunc("/", index)
	r.HandleFunc(`/static/{filename:.*\.coffee}.js`, coffeeHandler)
	r.HandleFunc("/static/{filename:.*}", staticHandler)
	r.Handle(`/websocket/`, websocket.Handler(wsockHandler)).Name("wsconn")
	http.Handle("/", r)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
