package sniffer

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSniffer(t *testing.T) {
	serverAddr := "127.0.0.1:1234"
	snifferAddr := "127.0.0.1:5678"

	serverOutput := bytes.NewBuffer(nil)
	clientOutput := bytes.NewBuffer(nil)
	snifferOutput := bytes.NewBuffer(nil)
	// The server
	serverDone := make(chan bool)
	go func() {
		l, err := net.Listen("tcp", serverAddr)
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("Error in server Accept: %v", err)
		}
		go func(c net.Conn) {
			buffer := make([]byte, 1024)
			defer func() {
				l.Close()
				close(serverDone)
			}()
			for {
				n, err := c.Read(buffer)
				if err == io.EOF {
					return
				} else if err != nil {
					t.Fatal(err)
				}
				serverOutput.Write(buffer[:n])
				fmt.Fprintf(c, "Received %s\n", buffer[:n])
			}
		}(conn)
	}()
	// The sniffer 
	var listener net.Listener
	go func() {
		var err error
		listener, err = net.Listen("tcp", snifferAddr)
		if err != nil {
			log.Fatalf("Error in listen for sniffer: %v", err)
		}
		Sniff(listener, serverAddr, snifferOutput)
	}()
	// The client
	conn, err := net.Dial("tcp", snifferAddr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		io.Copy(clientOutput, conn)
	}()
	delay := time.Microsecond * 1000
	io.WriteString(conn, "Foo!")
	time.Sleep(delay)
	io.WriteString(conn, "Bar!")
	time.Sleep(delay)
	conn.Close()
	<-serverDone
	listener.Close()

	expectedServer := `Foo!Bar!`
	expectedClient := "Received Foo!\nReceived Bar!\n"
	expectedSniffer :=
		`>>>>>>
Foo!
<<<<<<
Received Foo!

>>>>>>
Bar!
<<<<<<
Received Bar!

`
	if string(serverOutput.Bytes()) != expectedServer {
		t.Errorf("Server received %s", serverOutput.Bytes())
	}
	if string(clientOutput.Bytes()) != expectedClient {
		t.Errorf("Client received %s", clientOutput.Bytes())
	}
	if string(snifferOutput.Bytes()) != expectedSniffer {
		t.Errorf("Sniffer received %q", snifferOutput.Bytes())
	}

}

func TestHtml(t *testing.T) {
	serverAddr := "127.0.0.1:1234"
	snifferAddr := "127.0.0.1:5678"
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-type", "text/plain;charset=UTF-8")
		io.WriteString(w, "Ohai!")
	})
	go func() {
		http.ListenAndServe(serverAddr, nil)
	}()

	snifferOutput := bytes.NewBuffer(nil)
	go func() {
		l, err := net.Listen("tcp", snifferAddr)
		if err != nil {
			log.Fatalf("Error in listen for sniffer: %v", err)
		}
		Sniff(l, serverAddr, snifferOutput)
	}()

	r, err := http.Get("http://" + snifferAddr)
	if err != nil {
		t.Fatalf("Could not get html: %v", err)
	}
	fmt.Printf("Reading body\n")
	result, err := ioutil.ReadAll(r.Body)
	fmt.Printf("Read body\n")
	if string(result) != "Ohai!" || err != nil {
		t.Errorf("Result body was %s, error %v", result, err)
	}
	snifferExpected :=
		`>>>>>>
GET / HTTP/1.1
Host: 127.0.0.1:5678
User-Agent: Go http package
Accept-Encoding: gzip


<<<<<<
HTTP/1.1 200 OK
Content-Type: text/plain;charset=UTF-8
Date: ` + time.Now().UTC().Format(http.TimeFormat) + `
Transfer-Encoding: chunked

5
Ohai!
0


`
	snifferGot := strings.Replace(string(snifferOutput.Bytes()), "\r", "", -1)
	if snifferGot != snifferExpected {
		t.Errorf("Sniffer got %q\n", snifferGot)
	}
}
