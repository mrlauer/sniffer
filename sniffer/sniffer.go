/*
Package sniffer is a utility for intercepting communications and dumping the results.

A simple example:

	// In a proxy app waiting for connections from a client and connecting to a server
	go func() {
		l, err := net.Listen("tcp", snifferAddr)
		if err != nil {
			log.Fatalf("Error in listen for sniffer: %v", err)
		}
		Sniff(l, serverAddr, snifferOutput)
	}()
*/
package sniffer

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

// Sniffer passes data between a client and server (it doesn't really care which is which)
// and outputs data to its output writer.
type Sniffer struct {
	client     net.Conn
	server     net.Conn
	fromClient WriteFramer
	fromServer WriteFramer

	closed bool
	lock   sync.Mutex

	Id int
}

// Run sets up the read/write loops. It does not block.
func (s *Sniffer) Run() {
	bufSz := 4096
	// client -> server
	process := func(from io.ReadCloser, to io.WriteCloser, output *WriteFramer) {
		buffer := make([]byte, bufSz)
		for {
			n, errR := from.Read(buffer)
			var errW error
			if n > 0 {
				s.lock.Lock()
				(*output).WriteFrame(buffer[:n])
				s.lock.Unlock()
				_, errW = to.Write(buffer[:n])
			}
			// Distinguish between EOF and other errors?
			if errR != nil {
				if errW == nil {
					s.setClosed(to)
					return
				} else {
					s.setClosed(nil)
					return
				}
			} else if errW != nil {
				s.setClosed(from)
				return
			}
		}
	}
	go process(s.client, s.server, &s.fromClient)
	go process(s.server, s.client, &s.fromServer)
}

// setClosed sets the close flag and returns the previous status.
func (s *Sniffer) setClosed(conn io.Closer) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	old := s.closed
	s.closed = true
	if !old && conn != nil {
		conn.Close()
	}
	return old
}

// NewSniffer returns a new sniffer using the two connections.
// It does not start the sniffer.
func NewSniffer(client, server net.Conn, id int, fromClient, fromServer WriteFramer) *Sniffer {
	s := &Sniffer{client: client, server: server, Id: id, fromClient: fromClient, fromServer: fromServer}
	return s
}

func NewSnifferDefault(client, server net.Conn, id int, rawOutput io.Writer) *Sniffer {
	fromClient := PrefaceWriter(fmt.Sprintf(">>>>>> %d\n", id)).Transform(RawOutputFramer{rawOutput})
	fromServer := PrefaceWriter(fmt.Sprintf("<<<<<< %d\n", id)).Transform(RawOutputFramer{rawOutput})
	return NewSniffer(client, server, id, fromClient, fromServer)
}

type WriteFramer interface {
	WriteFrame(data ...[]byte) error
}

type RawOutputFramer struct {
	io.Writer
}

func (r RawOutputFramer) WriteFrame(data ...[]byte) error {
	for _, d := range data {
		_, err := io.Writer(r).Write(d)
		if err != nil {
			return err
		}
	}
	return nil
}

type WriteFramerFunc func(data ...[]byte) error

func (f WriteFramerFunc) WriteFrame(data ...[]byte) error {
	return f(data...)
}

type WriteFramerTransformer func(w WriteFramer, data ...[]byte) error

func (f WriteFramerTransformer) Transform(w WriteFramer) WriteFramer {
	return WriteFramerFunc(func(data ...[]byte) error {
		return f(w, data...)
	})
}

// OutputWrapper writes a preface before whatever it's writing.
func PrefaceWriter(preface string) WriteFramerTransformer {
	bpreface := []byte(preface)
	return func(w WriteFramer, data ...[]byte) error {
		todo := [][]byte{bpreface}
		return w.WriteFrame(append(todo, data...)...)
	}
}

// htmlHeaderSuppresser writes only the first line of html headers.
type HtmlHeaderSuppresser struct {
	w        io.Writer
	suppress bool
}

func (w *HtmlHeaderSuppresser) Write(data []byte) (int, error) {
	if w.suppress {
		// If the first line contains HTTP
		splits := bytes.SplitN(data, []byte("\r\n"), 1)
		if len(splits) > 1 && bytes.Contains(splits[0], []byte("HTTP/1.")) {
			// Get rid of everything through the double line
			headerBody := bytes.SplitN(splits[1], []byte("\r\n\r\n"), 1)
			buf := bytes.NewBuffer(nil)
			buf.Write(splits[0])
			if len(headerBody) > 1 {
				buf.Write(headerBody[1])
			}
			return w.w.Write(buf.Bytes())
		}
	}
	return w.w.Write(data)
}

// Sniff listens on the listener, dials the server when it gets a connection,
// and sniffs the resulting traffic.
func Sniff(listener net.Listener, serverAddr string, output io.Writer) {
	var id int
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return
		}
		serverConn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Printf("Error in Dial: %v\n", err)
			return
		}
		s := NewSnifferDefault(clientConn, serverConn, id, output)
		id++
		s.Run()
	}
}
