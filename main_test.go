package main

import (
	"fmt"
	"github.com/miekg/dns"
	"testing"
)

func Test_queryDNS(t *testing.T) {
	//queryDNS("paypal.com", "114.114.114.114:53")
	queryDNS("devepop.zoomdev.us", "223.5.5.5:53")
}

func Test_checkNXDomain(t *testing.T) {
	c := dns.Client{}
	isPass := isPoisoned(&c, "1.1.1.1")
	fmt.Println(isPass)
}
