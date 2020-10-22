package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	"golang.org/x/net/websocket"
)

var (
	tcpEnable bool
	tcpAddr   string
	tlsEnable bool
	tlsAddr   string
	tlsCert   string
	tlsKey    string
	wsEnable  bool
	wsAddr    string
	wssEnable bool
	wssAddr   string
	wssCert   string
	wssKey    string
	remote    string
)

func init() {
	flag.BoolVar(&tcpEnable, "tcp-enable", false, "enable tcp proxy")
	flag.StringVar(&tcpAddr, "tcp-addr", ":1883", "bind address for tcp proxy")
	flag.BoolVar(&tlsEnable, "tls-enable", false, "enable tls proxy")
	flag.StringVar(&tlsAddr, "tls-addr", ":8883", "bind address for tls proxy")
	flag.StringVar(&tlsCert, "tls-cert", "", "cert file for tls proxy")
	flag.StringVar(&tlsKey, "tls-key", "", "key file for tls proxy")
	flag.BoolVar(&wsEnable, "ws-enable", false, "enable ws proxy")
	flag.StringVar(&wsAddr, "ws-addr", ":8083", "bind address for ws proxy")
	flag.BoolVar(&wssEnable, "wss-enable", false, "enable wss proxy")
	flag.StringVar(&wssAddr, "wss-addr", ":8084", "bind address for wss proxy")
	flag.StringVar(&wssCert, "wss-cert", "", "cert file for wss proxy")
	flag.StringVar(&wssKey, "wss-key", "", "key file for wss proxy")
	flag.StringVar(&remote, "remote", "", "remote address for upstream")
	flag.Parse()
}

func proxy(conn io.ReadWriteCloser) {
	peer, err := net.Dial("tcp", remote)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}

	go func() {
		if _, err := io.Copy(peer, conn); err != nil {
			log.Println(err)
			peer.Close()
			conn.Close()
			return
		}
	}()
	if _, err := io.Copy(conn, peer); err != nil {
		log.Println(err)
		peer.Close()
		conn.Close()
		return
	}
}

func main() {

	if remote == "" {
		flag.Usage()
		return
	}

	if tcpEnable {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("TCP proxy at %s started\n", tcpAddr)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				go proxy(conn)
			}
		}()
	}

	if tlsEnable {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Fatal(err)
		}
		ln, err := tls.Listen("tcp", tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("TLS proxy at %s started\n", tlsAddr)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					log.Println(err)
					continue
				}
				go proxy(conn)
			}
		}()
	}

	if wsEnable {
		go func() {
			log.Printf("WS proxy at %s started\n", wsAddr)
			if err := http.ListenAndServe(wsAddr, websocket.Handler(func(conn *websocket.Conn) {
				conn.PayloadType = websocket.BinaryFrame
				proxy(conn)
			})); err != nil {
				log.Fatal(err)
			}
		}()
	}

	if wssEnable {
		go func() {
			log.Printf("WSS proxy at %s started\n", wssAddr)
			if err := http.ListenAndServeTLS(wssAddr, wssCert, wssKey, websocket.Handler(func(conn *websocket.Conn) {
				conn.PayloadType = websocket.BinaryFrame
				proxy(conn)
			})); err != nil {
				log.Fatal(err)
			}
		}()
	}

	ch := make(chan os.Signal, 1)
	exit := make(chan bool)
	signal.Notify(ch, os.Interrupt)
	go func() {
		for range ch {
			exit <- true
		}
	}()
	<-exit
}
