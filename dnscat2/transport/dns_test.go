package transport

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSRoundTripAllRecordTypes(t *testing.T) {
	for _, domain := range []string{"", "tunnel.example.com"} {
		codec, err := NewCodec(domain)
		if err != nil {
			t.Fatal(err)
		}
		for _, recordType := range []uint16{dns.TypeTXT, dns.TypeCNAME, dns.TypeMX, dns.TypeA, dns.TypeAAAA} {
			payload := []byte("dnscat2 payload \x00\xff")
			query, err := codec.BuildQuery(1234, recordType, payload)
			if err != nil {
				t.Fatal(err)
			}
			packedQuery, err := query.Pack()
			if err != nil {
				t.Fatal(err)
			}
			unpackedQuery := new(dns.Msg)
			if err := unpackedQuery.Unpack(packedQuery); err != nil {
				t.Fatal(err)
			}
			decodedQuery, err := codec.DecodeQuery(unpackedQuery)
			if err != nil || !bytes.Equal(decodedQuery, payload) {
				t.Fatalf("query domain=%q type=%d: %x %v", domain, recordType, decodedQuery, err)
			}
			response, err := codec.BuildResponse(unpackedQuery, payload)
			if err != nil {
				t.Fatal(err)
			}
			packedResponse, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			unpackedResponse := new(dns.Msg)
			if err := unpackedResponse.Unpack(packedResponse); err != nil {
				t.Fatal(err)
			}
			decodedResponse, err := codec.DecodeResponse(unpackedResponse, 1234, recordType)
			if err != nil || !bytes.Equal(decodedResponse, payload) {
				t.Fatalf("response domain=%q type=%d: %x %v", domain, recordType, decodedResponse, err)
			}
		}
	}
}

func TestAddressResponseCanBeReordered(t *testing.T) {
	codec, _ := NewCodec("")
	query, _ := codec.BuildQuery(1, dns.TypeA, []byte("query"))
	response, err := codec.BuildResponse(query, []byte("response payload"))
	if err != nil {
		t.Fatal(err)
	}
	for left, right := 0, len(response.Answer)-1; left < right; left, right = left+1, right-1 {
		response.Answer[left], response.Answer[right] = response.Answer[right], response.Answer[left]
	}
	decoded, err := codec.DecodeResponse(response, 1, dns.TypeA)
	if err != nil || string(decoded) != "response payload" {
		t.Fatalf("got %q, %v", decoded, err)
	}
}

func TestPayloadLimitAndDomainValidation(t *testing.T) {
	codec, err := NewCodec("tunnel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if codec.MaxPayload() <= 0 || codec.MaxPayload() > maxResponseBytes {
		t.Fatalf("payload limit: %d", codec.MaxPayload())
	}
	if len(codec.EncodeQueryName(make([]byte, codec.MaxPayload()))) > 254 {
		t.Fatal("maximum payload produces an invalid DNS name")
	}
	if _, err := NewCodec("bad_domain..example"); err == nil {
		t.Fatal("invalid domain accepted")
	}
}

func TestRejectWrongDomain(t *testing.T) {
	codec, _ := NewCodec("tunnel.example.com")
	other, _ := NewCodec("other.example.net")
	query, _ := other.BuildQuery(1, dns.TypeTXT, []byte("query"))
	if _, err := codec.DecodeQuery(query); err == nil {
		t.Fatal("wrong domain accepted")
	}
}
