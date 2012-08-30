/*
A simple "proxy server" that dumps all its traffic to stdout
*/
package main

import (
	"flag"
	"fmt"
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
	suppressHeaders := flag.Bool("h", false, "Suppress most HTML headers")

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

	var suppr sniffer.WriteFramerTransformer = func(w sniffer.WriteFramer, s *sniffer.Sniffer, data ...[]byte) error {
		if *suppressHeaders {
			return sniffer.SuppressHtmlHeaders(w, s, data...)
		}
		return w.WriteFrame(s, data...)
	}

	// Yucky ui to toggle header suppression
	go func() {
		var s string
		for {
			_, err := fmt.Scanf("%s", &s)
			if err == io.EOF {
				return
			}
			if s == "h" {
				*suppressHeaders = !*suppressHeaders
			}
		}
	}()

	l, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Error in listen for sniffer: %v", err)
	}
	fromClient, fromServer := sniffer.DefaultWriteFramers(os.Stdout)
	fromClient = suppr.Transform(fromClient)
	fromServer = suppr.Transform(fromServer)
	sniffer.SniffToOutput(l, server, fromClient, fromServer)
}
