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
	fromClient io.Writer
	fromServer io.Writer

	closed bool
	lock   sync.Mutex

	Id int
}

// Run sets up the read/write loops. It does not block.
func (s *Sniffer) Run() {
	bufSz := 4096
	// client -> server
	process := func(from io.ReadCloser, to io.WriteCloser, output *io.Writer) {
		buffer := make([]byte, bufSz)
		for {
			n, errR := from.Read(buffer)
			var errW error
			if n > 0 {
				(*output).Write(buffer[:n])
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
func NewSniffer(client, server net.Conn, id int, rawOutput io.Writer) *Sniffer {
	s := &Sniffer{client: client, server: server, Id: id}
	s.fromClient = &outputWrapper{rawOutput, fmt.Sprintf(">>>>>> %d\n", id)}
	s.fromServer = &outputWrapper{rawOutput, fmt.Sprintf("<<<<<< %d\n", id)}
	return s
}

// outputWrapper writes a preface before whatever it's writing.
type outputWrapper struct {
	w       io.Writer
	preface string
}

func (w *outputWrapper) Write(data []byte) (int, error) {
	_, err := io.WriteString(w.w, w.preface)
	if err != nil {
		return 0, err
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
		s := NewSniffer(clientConn, serverConn, id, output)
		id++
		s.Run()
	}
}
