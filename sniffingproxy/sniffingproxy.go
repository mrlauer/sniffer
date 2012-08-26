/*
A simple "proxy server" that dumps all its traffic to stdout
*/
package main

import (
	"flag"
	"github.com/mrlauer/sniffer/sniffer"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	// Redirect logging output.
	log.SetOutput(os.Stderr)

	pport := flag.String("local", "", "Address to listen on")
	pserver := flag.String("remote", "", "Remote server to dial")
	ptestserver := flag.Bool("testserver", false, "Run as a simple http server, for testing purposes")

	flag.Parse()
	port := *pport
	server := *pserver
	testserver := *ptestserver

	if port == "" {
		log.Fatal("Please specify a port to listen on.")
	}
	if server == "" && !testserver {
		log.Fatal("Please specify a server to to connect to.")
	}

	if testserver {
		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			body, _ := ioutil.ReadAll(req.Body)
			req.Body.Close()
			w.Header().Set("Content-type", "text/plain")
			io.WriteString(w, "Serving...\n")
			w.Write(body)
		})
		log.Fatal(http.ListenAndServe(port, nil))
	}

	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Error in listen for sniffer: %v", err)
	}
	sniffer.Sniff(l, server, os.Stdout)
}
