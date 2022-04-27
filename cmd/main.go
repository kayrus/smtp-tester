package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/mail"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	errReplace1 = regexp.MustCompile(`(.*) [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(.*)`)
	errReplace2 = regexp.MustCompile(`(.*) [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+->[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(.*)`)
	lck         = &sync.RWMutex{}
	errs        = make(map[string]uint64)
	totalReq    = new(uint64)
	totalErr    = new(uint64)
	fps         = new(uint64)
	ops         = new(uint64)
)

type config struct {
	sync.Mutex
	Debug      bool
	SMTPHost   string
	Username   string
	Password   string
	Subject    string
	From       *mail.Address
	HeaderFrom *mail.Address
	To         *mail.Address
	ShowErr    bool
	StartTLS   bool
	Threads    uint
	Timeout    time.Duration
	Size       uint
	MaxMails   uint64
	ReuseSMTP  bool
	Msg        *strings.Reader
	Auth       sasl.Client
	WG         sync.WaitGroup
	Client     *smtp.Client
}

func (cfg *config) trackErr(stage string, err error, limiter chan struct{}) {
	atomic.AddUint64(fps, 1)
	if limiter == nil {
		log.Print(err)
		os.Exit(1)
	}

	if !cfg.ShowErr {
		<-limiter
		return
	}

	switch err := err.(type) {
	case *net.OpError:
		// put all "connection reset by peer" errors under one group
		if addr, ok := err.Source.(*net.TCPAddr); ok {
			addr.Port = 65535
		}
	case *smtp.SMTPError:
		if err.Code == 554 {
			if strings.Contains(err.Message, "dial tcp") {
				err.Message = errReplace1.ReplaceAllString(err.Message, `$1 backend$2`)
			} else {
				err.Message = errReplace2.ReplaceAllString(err.Message, `$1 smtp:65535->backend$2`)
			}
		}
	}
	errType := fmt.Sprintf("%s: %s", stage, err)
	lck.Lock()
	errs[errType] += 1
	lck.Unlock()

	<-limiter
}

func (cfg *config) sendMultiple(n uint64, limiter chan struct{}) {
	defer cfg.WG.Done()

	atomic.AddUint64(ops, 1)

	// single email at once
	cfg.Lock()
	defer cfg.Unlock()

	c := cfg.Client
	defer c.Reset()
	err := c.Mail(cfg.From.Address, nil)
	if err != nil {
		cfg.trackErr("mail", err, limiter)
		return
	}

	err = c.Rcpt(cfg.To.Address)
	if err != nil {
		cfg.trackErr("rcpt", err, limiter)
		return
	}

	w, err := c.Data()
	if err != nil {
		cfg.trackErr("data", err, limiter)
		return
	}

	_, err = io.Copy(w, cfg.Msg)
	if err != nil {
		w.Close()
		cfg.trackErr("copy", err, limiter)
		return
	}

	err = w.Close()
	if err != nil {
		cfg.trackErr("close", err, limiter)
		return
	}

	if limiter == nil {
		return
	}

	<-limiter
}

func getClient(cfg *config) (*smtp.Client, error) {
	conn, tlsConfig, err := initConn(cfg)
	if err != nil {
		return nil, err
	}

	// Set custom timeouts
	c := &smtp.Client{
		CommandTimeout:    cfg.Timeout,
		SubmissionTimeout: cfg.Timeout,
	}
	err = c.InitConn(conn)
	if err != nil {
		return nil, err
	}

	hostname := "test"
	err = c.Hello(hostname)
	if err != nil {
		return nil, err
	}

	if _, ok := conn.(*tls.Conn); !ok && cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err = c.StartTLS(tlsConfig); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if err = c.Auth(cfg.Auth); err != nil {
		return nil, err
	}

	return c, nil
}

func (cfg *config) sendSingle(n uint64, limiter chan struct{}) {
	defer cfg.WG.Done()

	atomic.AddUint64(ops, 1)

	conn, tlsConfig, err := initConn(cfg)
	if err != nil {
		cfg.trackErr("dial", err, limiter)
		return
	}
	defer conn.Close()

	// Set custom timeouts
	c := &smtp.Client{
		CommandTimeout:    cfg.Timeout,
		SubmissionTimeout: cfg.Timeout,
	}
	err = c.InitConn(conn)
	if err != nil {
		cfg.trackErr("init", err, limiter)
		return
	}

	defer c.Quit()

	hostname := fmt.Sprintf("test%d", n)
	err = c.Hello(hostname)
	if err != nil {
		cfg.trackErr("hello", err, limiter)
		return
	}

	if _, ok := conn.(*tls.Conn); !ok && cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err = c.StartTLS(tlsConfig); err != nil {
				cfg.trackErr("starttls", err, limiter)
				return
			}
		} else {
			cfg.trackErr("starttls", fmt.Errorf("starttls is required"), limiter)
			return
		}
	}

	if err = c.Auth(cfg.Auth); err != nil {
		cfg.trackErr("auth", err, limiter)
		return
	}

	err = c.SendMail(cfg.From.Address, []string{cfg.To.Address}, cfg.Msg)
	if err != nil {
		cfg.trackErr("send", err, limiter)
		return
	}

	if limiter == nil {
		return
	}

	<-limiter
}

func randStringBytes(n uint) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func monitor(showErr bool) {
	for {
		select {
		case <-time.After(1 * time.Second):
			f := atomic.SwapUint64(fps, 0)
			s := atomic.SwapUint64(ops, 0)
			tS := atomic.AddUint64(totalReq, s)
			tF := atomic.AddUint64(totalErr, f)
			var perc uint64
			var tPerc uint64
			if s > 0 {
				perc = 100 * f / s
			}
			if tS > 0 {
				tPerc = 100 * tF / tS
			}
			log.Printf("%d rps, %d failed (%d%%)", s, f, perc)
			log.Printf("total %d requests, %d successful, %d failed (%d%%)", tS, tS-tF, tF, tPerc)
			if showErr {
				lck.RLock()
				for k, v := range errs {
					log.Printf("ERROR: %s -> %d", k, v)
				}
				lck.RUnlock()
			}
			/*
			   if s == 0 {
			           log.Fatalf("stop")
			   }
			*/
		}
	}
}

func initConn(cfg *config) (net.Conn, *tls.Config, error) {
	h, p, _ := net.SplitHostPort(cfg.SMTPHost)
	if p == "465" {
		tlsConfig := &tls.Config{
			ServerName: h,
		}
		tlsDialer := tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout: cfg.Timeout,
			},
			Config: tlsConfig,
		}
		conn, err := tlsDialer.Dial("tcp", cfg.SMTPHost)
		return conn, tlsConfig, err
	}

	tlsConfig := &tls.Config{
		ServerName: h,
	}
	conn, err := net.DialTimeout("tcp", cfg.SMTPHost, cfg.Timeout)
	return conn, tlsConfig, err
}

func main() {
	var cfg config
	var from, headerFrom, to string
	var timeout uint
	flag.StringVar(&cfg.SMTPHost, "smtp-host", "", "SMTP server address")
	flag.StringVar(&cfg.Username, "username", "", "SMTP server username")
	flag.StringVar(&cfg.Password, "password", "", "SMTP server password")
	flag.StringVar(&cfg.Subject, "subject", "hello", "Email subject")
	flag.StringVar(&from, "from", "", "Envelope from sender address")
	flag.StringVar(&headerFrom, "header-from", "", "Header from sender address, if empty defaults to --from")
	flag.StringVar(&to, "to", "", "Recipient address")
	flag.UintVar(&cfg.Threads, "threads", 0, "Whether to run an infinite loop with an amount of threads")
	flag.UintVar(&timeout, "timeout", 3, "Timeout in seconds")
	flag.UintVar(&cfg.Size, "size", 30720, "Message size in bytes")
	flag.Uint64Var(&cfg.MaxMails, "max-mails", 0, "Limit the amount of emails, 0 means no limit")
	flag.BoolVar(&cfg.Debug, "debug", false, "show debug logs")
	flag.BoolVar(&cfg.ShowErr, "show-error", false, "show error type on auth failure")
	flag.BoolVar(&cfg.StartTLS, "starttls", true, "whether to require StartTLS")
	flag.BoolVar(&cfg.ReuseSMTP, "reuse-smtp", false, "Reuse SMTP connection")
	flag.Parse()

	// SMTP credentials
	if cfg.SMTPHost == "" {
		log.Fatalf("Please define --smtp-host argument")
	}

	if cfg.Username == "" {
		log.Fatalf("Please define --username argument")
	}

	if cfg.Password == "" {
		log.Fatalf("Please define --password argument")
	}

	if cfg.ReuseSMTP && cfg.Threads != 1 {
		log.Fatalf("Multiple threads with reusing SMTP connection is not supported")
	}

	// Sender and recipient
	var err error
	cfg.From, err = mail.ParseAddress(from)
	if err != nil {
		log.Fatalf("Invalid --from argument: %s", err)
	}
	cfg.To, err = mail.ParseAddress(to)
	if err != nil {
		log.Fatalf("Invalid --to argument: %s", err)
	}
	if headerFrom != "" {
		cfg.HeaderFrom, err = mail.ParseAddress(headerFrom)
		if err != nil {
			log.Fatalf("Invalid --header-from argument: %s", err)
		}
	} else {
		cfg.HeaderFrom = cfg.From
	}

	// other parameters
	cfg.Timeout = time.Second * time.Duration(timeout)
	cfg.Auth = sasl.NewPlainClient("", cfg.Username, cfg.Password)
	cfg.Msg = strings.NewReader("To: " + cfg.To.Address + "\r\n" +
		"From: " + cfg.HeaderFrom.String() + "\r\n" +
		"Subject: " + cfg.Subject + "\r\n" +
		"\r\n" +
		randStringBytes(cfg.Size) +
		"\r\n")

	var send func(n uint64, limiter chan struct{})
	if cfg.ReuseSMTP {
		cfg.Client, err = getClient(&cfg)
		if err != nil {
			log.Fatalf("failed to initalize a client: %s", err)
		}
		log.Printf("initialized a client")
		send = cfg.sendMultiple
	} else {
		send = cfg.sendSingle
	}

	if cfg.Threads == 0 {
		send(0, nil)
		os.Exit(0)
	}

	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

	// stats monitor
	go monitor(cfg.ShowErr)

	// main loop
	var count uint64
	limiter := make(chan struct{}, cfg.Threads)
	for {
		select {
		case <-exit:
			log.Printf("Interrupted")
			log.Printf("waiting for all threads to stop")
			cfg.WG.Wait()
			log.Printf("Sleeping for 3 seconds")
			time.Sleep(3 * time.Second)
			log.Printf("done")
			return
		default:
			if cfg.MaxMails > 0 && count >= cfg.MaxMails {
				// stop on reaching the max emails limit
				cfg.WG.Wait()
				log.Printf("Sleeping for 3 seconds")
				time.Sleep(3 * time.Second)
				log.Printf("done")
				return
			}
			count++
			limiter <- struct{}{}
			cfg.WG.Add(1)
			go send(count, limiter)
		}
	}
}
