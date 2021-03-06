/*
websniffer runs a tcp proxy server with a web control panel.

  websniffer -addr=":8080"

runs an http server on port 8080. Navigate to that page, enter local and remote addresses, and hit Start.
All the traffic will be dumped to the browser window. Output from different connections will be conveniently color-coded.
If the traffic appears to be http, the headers will appear in boldface with all but the first line hidden. Click on the
header to toggle display of the whole thing. Message bodies will not be decoded.

websniffer requires a browser that supports websockets.
*/
package main

import (
	"bytes"
	"code.google.com/p/go.net/websocket"
	"code.google.com/p/gorilla/mux"
	"flag"
	"fmt"
	"github.com/mrlauer/sniffer/sniffer"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"time"
	"unicode"
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

func sendMessage(ws *websocket.Conn, key, text string) {
	websocket.JSON.Send(ws, map[string]interface{}{
		key: text,
	})
}

func wsockHandler(ws *websocket.Conn) {
	// Start a sniffer.
	req := ws.Request()
	req.ParseForm()
	local := req.Form.Get("local")
	remote := req.Form.Get("remote")

	if local != "" && remote != "" {
		l, err := net.Listen("tcp", local)
		if err != nil {
			sendMessage(ws, "error", err.Error())
			ws.Close()
			return
		}

		go func() {
			buf := make([]byte, 256)
			for {
				_, err := ws.Read(buf)
				if err != nil {
					l.Close()
					return
				}
			}
		}()

		fn := func(m map[string]interface{}) error {
			return websocket.JSON.Send(ws, m)
		}
		fromClient := webSniffer{fn, true}
		fromServer := webSniffer{fn, false}
		err = sniffer.SniffToOutput(l, remote, fromClient, fromServer)
		ws.Close()
	}
}

func index(w http.ResponseWriter, r *http.Request, local, remote string) {
	t, err := template.ParseFiles(path.Join(TemplateDir, "websniffer.html"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b := bytes.NewBuffer(nil)
	err = t.Execute(b, map[string]string{
		"local":  local,
		"remote": remote,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-type", "text/html")
	w.Write(b.Bytes())
}

func makeIndex(local, remote string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		index(w, r, local, remote)
	}
}

// Channel sniffed stuff to a function
type webSniffer struct {
	fn         func(map[string]interface{}) error
	FromClient bool
}

func (w webSniffer) WriteFrame(s *sniffer.Sniffer, dataIn ...[]byte) error {
	data := string(bytes.Join(dataIn, nil))
	data = strings.TrimLeftFunc(data, unicode.IsSpace)
	splits := strings.SplitN(data, "\r\n", 2)
	todo := map[string]interface{}{
		"id":         s.Id,
		"fromClient": w.FromClient,
	}
	if len(splits) > 1 && strings.Contains(splits[0], "HTTP/1.") {
		headerBody := strings.SplitN(data, "\r\n\r\n", 2)
		todo["header"] = (headerBody[0])
		todo["body"] = headerBody[1]
	} else {
		todo["body"] = data
	}

	return w.fn(todo)
}

func main() {
	addr := flag.String("addr", ":8080", "address of the sniffer web interface")
	local := flag.String("local", "localhost:8081", "local address to proxy")
	remote := flag.String("remote", "localhost:8082", "remote address to proxy")

	flag.Parse()

	r := mux.NewRouter()
	r.HandleFunc("/", makeIndex(*local, *remote))
	r.HandleFunc(`/static/{filename:.*\.coffee}.js`, coffeeHandler)
	r.HandleFunc("/static/{filename:.*}", staticHandler)
	r.Handle(`/websocket/`, websocket.Handler(wsockHandler)).Name("wsconn")
	http.Handle("/", r)
	fmt.Printf("Listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
