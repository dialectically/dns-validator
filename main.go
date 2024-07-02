package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

// Define flags similar to Python script's input parser

var (
	baselines      = []string{"1.1.1.1", "8.8.8.8"}
	targetRoot     = "devepapps.zoomdev.us"
	targetRootIp   string
	nxdomainChecks = []string{"facebook.com", "paypal.com", "google.com", "bet365.com", "nonexist123.com", "zoomdev.us"}
)

// randString generates a random string of 10 lowercase letters
func randString() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	s := make([]rune, 10)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

// validIPAddress checks if the given string is a valid IPv4 or IPv6 address
func validIPAddress(IP string) bool {
	if net.ParseIP(IP) != nil {
		return true
	}
	return false
}

var (
	resolverList string
	threads      int
	outputFile   string
)

func main() {

	flag.StringVar(&resolverList, "r", "resolvers.txt", "-r resolvers.txt")
	flag.IntVar(&threads, "t", 100, "Number of concurrent threads")
	flag.StringVar(&outputFile, "o", "verify-resolvers.txt", "-o xx.txt")
	flag.Parse()

	checkBaseLine()

	outputfile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer outputfile.Close()

	rand.Seed(time.Now().UnixNano())
	jobQueue := make(chan string, 500)
	resultQueue := make(chan string, 500)
	var wg sync.WaitGroup

	file, err := os.Open(resolverList)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	//var rlist []string

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(jobQueue, resultQueue, &wg)
	}

	go func() {
		for s := range resultQueue {
			//output to file
			outputfile.WriteString(s + "\n")
		}
	}()

	for scanner.Scan() {
		//rlist = append(rlist, scanner.Text())
		jobQueue <- scanner.Text()
	}

	close(jobQueue)

	wg.Wait()

}

func worker(jobQueue <-chan string, resultQueue chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	c := dns.Client{}
	c.Timeout = 2 * time.Second
	for dnsServer := range jobQueue {
		s := dnsServer
		now := time.Now()

		if isPoisoned(&c, s) {
			log.Println("DNS poison Detected", s)
			continue
		}

		m := dns.Msg{}
		m.SetQuestion(dns.Fqdn(targetRoot), dns.TypeA)
		r, _, err := c.Exchange(&m, s+":53")
		if err != nil {
			log.Println(err)
			continue
		}
		if len(r.Answer) > 0 {
			if a, ok := r.Answer[0].(*dns.A); ok {
				if a.A.String() != targetRootIp {
					log.Println("DNS Hijacking Detected", s)
				} else {
					log.Println("DNS checked pass", s)
					resultQueue <- s
				}
			}
		}

		since := time.Since(now)
		log.Println("task", s, "spent", since)
	}
}

func isPoisoned(dnsClient *dns.Client, server string) bool {
	for _, nxdomain := range nxdomainChecks {
		m := dns.Msg{}
		m.SetQuestion(dns.Fqdn(fmt.Sprintf("%s.%s", randString(), nxdomain)), dns.TypeA)
		r, _, err := dnsClient.Exchange(&m, server+":53")
		if err != nil {
			log.Println("checking nx domain ", err)
			continue
		}
		if r.Rcode == dns.RcodeSuccess {
			return true
		}
	}

	return false
}

func checkBaseLine() {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(targetRoot), dns.TypeA)
	r, _, err := c.Exchange(&m, "1.1.1.1:53")
	if err != nil {
		log.Println("base line check failed")
		panic(err)
	}
	if len(r.Answer) > 0 {
		if a, ok := r.Answer[0].(*dns.A); ok {
			targetRootIp = a.A.String()
			fmt.Println("target root ip", targetRoot, targetRootIp)
		}
	}
}

func queryDNS(domain, server string) (string, error) {
	c := dns.Client{}
	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, _, err := c.Exchange(&m, server)
	if err != nil {
		return "", err
	}
	if len(r.Answer) > 0 {
		//if a, ok := r.Answer[0].(*dns.A); ok {
		//	return a.A.String(), nil
		//}
		for _, answer := range r.Answer {
			if answerA, ok := answer.(*dns.A); ok {
				fmt.Println(answerA.A.String())
			}
		}
	}
	return "", fmt.Errorf("no A record found")
}
