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
	"sync"
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
	io.WriteString(conn, "Foo!\n")
	time.Sleep(delay)
	io.WriteString(conn, "Bar!\n")
	time.Sleep(delay)
	conn.Close()
	<-serverDone
	listener.Close()

	expectedServer := "Foo!\nBar!\n"
	expectedClient := "Received Foo!\n\nReceived Bar!\n\n"
	expectedSniffer :=
		`>>>>>> 0
Foo!
<<<<<< 0
Received Foo!

>>>>>> 0
Bar!
<<<<<< 0
Received Bar!

`
	if string(serverOutput.Bytes()) != expectedServer {
		t.Errorf("Server received %q", serverOutput.Bytes())
	}
	if string(clientOutput.Bytes()) != expectedClient {
		t.Errorf("Client received %s", clientOutput.Bytes())
	}
	if string(snifferOutput.Bytes()) != expectedSniffer {
		t.Errorf("Sniffer received %q", snifferOutput.Bytes())
	}

}

func doTestHtml(t *testing.T, trans WriteFramerTransformer, snifferExpected func() string) {
	http.DefaultServeMux = http.NewServeMux()
	serverAddr := "127.0.0.1:1234"
	snifferAddr := "127.0.0.1:5678"

	// Make sure we wait until everything is done
	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()
	kill := make(chan bool)
	defer close(kill)

	// Don't keep idle connections
	defer http.DefaultTransport.(*http.Transport).CloseIdleConnections()

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-type", "text/plain;charset=UTF-8")
		io.WriteString(w, "Ohai!")
	})
	go func() {
		l, err := net.Listen("tcp", serverAddr)
		if err != nil {
			log.Fatal(err)
			t.Errorf("Error in net.Listen: %v\n", err)
		}
		go http.Serve(l, nil)
		<-kill
		l.Close()
		wg.Done()
	}()

	snifferOutput := bytes.NewBuffer(nil)
	go func() {
		l, err := net.Listen("tcp", snifferAddr)
		if err != nil {
			log.Fatal(err)
			t.Errorf("Error in listen for sniffer: %v", err)
		}
		fromClient, fromServer := DefaultWriteFramers(snifferOutput)
		if trans != nil {
			fromClient = trans.Transform(fromClient)
			fromServer = trans.Transform(fromServer)
		}
		go func() {
			SniffToOutput(l, serverAddr, fromClient, fromServer)
		}()
		<-kill
		l.Close()
		wg.Done()
	}()

	r, err := http.Get("http://" + snifferAddr)
	if err != nil {
		t.Fatalf("Could not get html: %v", err)
	}
	result, err := ioutil.ReadAll(r.Body)
	if string(result) != "Ohai!" || err != nil {
		t.Errorf("Result body was %s, error %v", result, err)
	}
	snifferGot := strings.Replace(string(snifferOutput.Bytes()), "\r", "", -1)
	exp := snifferExpected()
	if snifferGot != exp {
		t.Errorf("Sniffer got \n%q\n, not\n%q\nat %v", snifferGot, exp, time.Now())
	}
}

func TestHtml(t *testing.T) {
	snifferExpected := func() string {
		return `>>>>>> 0
GET / HTTP/1.1
Host: 127.0.0.1:5678
User-Agent: Go http package
Accept-Encoding: gzip

<<<<<< 0
HTTP/1.1 200 OK
Content-Type: text/plain;charset=UTF-8
Date: ` + time.Now().UTC().Format(http.TimeFormat) + `
Transfer-Encoding: chunked

5
Ohai!
0

`
	}
	doTestHtml(t, nil, snifferExpected)
}

func TestHtmlSuppressHeaders(t *testing.T) {
	snifferExpected := func() string {
		return `>>>>>> 0
GET / HTTP/1.1
<<<<<< 0
HTTP/1.1 200 OK
5
Ohai!
0

`
	}
	doTestHtml(t, WriteFramerTransformer(SuppressHtmlHeaders), snifferExpected)
}

func TestHtmlHeaderSuppresserFunc(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := RawOutputFramer{buf}

	msg1 := `GET / HTTP/1.1
Host: 127.0.0.1:5678
User-Agent: Go http package
Accept-Encoding: gzip

5
Ohai!
0


`
	msg2 := `HTTP/1.1 200 OK
Content-Type: text/plain;charset=UTF-8
Date: ` + time.Now().UTC().Format(http.TimeFormat) + `
Transfer-Encoding: chunked

5
hello
0


`
	expected := `GET / HTTP/1.1
5
Ohai!
0


HTTP/1.1 200 OK
5
hello
0


`

	msg1 = strings.Replace(msg1, "\n", "\r\n", -1)
	msg2 = strings.Replace(msg2, "\n", "\r\n", -1)

	SuppressHtmlHeaders(w, nil, []byte(msg1))
	SuppressHtmlHeaders(w, nil, []byte(msg2))
	s := strings.Replace(string(buf.Bytes()), "\r\n", "\n", -1)
	if s != expected {
		t.Errorf("Got %s\n", s)
	}
}
