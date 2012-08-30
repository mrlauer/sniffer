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
	"unicode"
)

func join(data ...[]byte) []byte {
	return bytes.Join(data, nil)
}

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
	process := func(from io.ReadCloser, to io.WriteCloser, output WriteFramer) {
		buffer := make([]byte, bufSz)
		for {
			n, errR := from.Read(buffer)
			var errW error
			if n > 0 {
				s.lock.Lock()
				output.WriteFrame(s, buffer[:n])
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
	go process(s.client, s.server, s.fromClient)
	go process(s.server, s.client, s.fromServer)
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

func makePrefacer(format string) WriteFramerTransformer {
	return PrefaceWriter(func(s *Sniffer) []byte {
		return []byte(fmt.Sprintf(format, s.Id))
	})
}

func DefaultWriteFramers(rawOutput io.Writer) (fromClient, fromServer WriteFramer) {
	fromClient = makePrefacer(">>>>>> %d\n").Transform(RawOutputFramer{rawOutput})
	fromServer = makePrefacer("<<<<<< %d\n").Transform(RawOutputFramer{rawOutput})
	return
}

type WriteFramer interface {
	WriteFrame(s *Sniffer, data ...[]byte) error
}

type RawOutputFramer struct {
	io.Writer
}

func (r RawOutputFramer) WriteFrame(s *Sniffer, data ...[]byte) error {
	for _, d := range data {
		_, err := io.Writer(r).Write(d)
		if err != nil {
			return err
		}
	}
	return nil
}

type WriteFramerFunc func(s *Sniffer, data ...[]byte) error

func (f WriteFramerFunc) WriteFrame(s *Sniffer, data ...[]byte) error {
	return f(s, data...)
}

type WriteFramerTransformer func(w WriteFramer, s *Sniffer, data ...[]byte) error

func (f WriteFramerTransformer) Transform(w WriteFramer) WriteFramer {
	return WriteFramerFunc(func(s *Sniffer, data ...[]byte) error {
		return f(w, s, data...)
	})
}

// OutputWrapper writes a preface before whatever it's writing.
func PrefaceWriter(preface func(s *Sniffer) []byte) WriteFramerTransformer {
	return func(w WriteFramer, s *Sniffer, data ...[]byte) error {
		todo := [][]byte{preface(s)}
		todo = append(todo, data...)
		nl := []byte{'\n'}
		if len(data) > 0 && !bytes.HasSuffix(data[len(data)-1], nl) {
			todo = append(todo, nl)
		}
		return w.WriteFrame(s, todo...)
	}
}

// SuppressHtmlHeaders writes only the first line of html headers.
func SuppressHtmlHeaders(w WriteFramer, s *Sniffer, dataIn ...[]byte) error {
	data := join(dataIn...)
	// If the first line contains HTTP
	data = bytes.TrimLeftFunc(data, unicode.IsSpace)
	splits := bytes.SplitN(data, []byte("\r\n"), 2)
	if len(splits) > 1 && bytes.Contains(splits[0], []byte("HTTP/1.")) {
		// Get rid of everything through the double line
		headerBody := bytes.SplitN(splits[1], []byte("\r\n\r\n"), 2)
		first := splits[0]
		var rest []byte
		if len(headerBody) > 1 {
			rest = headerBody[1]
		}
		return w.WriteFrame(s, first, []byte("\n"), rest)
	}
	return w.WriteFrame(s, dataIn...)
}

// Sniff listens on the listener, dials the server when it gets a connection,
// and sniffs the resulting traffic.
func Sniff(listener net.Listener, serverAddr string, output io.Writer) error {
	fromClient, fromServer := DefaultWriteFramers(output)
	return SniffToOutput(listener, serverAddr, fromClient, fromServer)
}

// Sniff listens on the listener, dials the server when it gets a connection,
// and sniffs the resulting traffic.
func SniffToOutput(listener net.Listener, serverAddr string, fromClient, fromServer WriteFramer) error {
	var id int
	for {
		clientConn, err := listener.Accept()
		if err != nil {
			return err
		}
		serverConn, err := net.Dial("tcp", serverAddr)
		if err != nil {
			log.Printf("Error in Dial: %v\n", err)
			return err
		}
		s := NewSniffer(clientConn, serverConn, id, fromClient, fromServer)
		id++
		s.Run()
	}
	return nil
}
