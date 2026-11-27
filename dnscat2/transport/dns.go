// Package transport implements the DNS transport encoding used by dnscat2.
package transport

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

const (
	maxResponseBytes = 120 // Upstream's TXT/CNAME/MX response limit is 241 hex bytes.
	wildcardPrefix   = "dnscat"
)

type Codec struct {
	Domain string
}

func NewCodec(domain string) (*Codec, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain != "" {
		if _, ok := dns.IsDomainName(domain); !ok {
			return nil, errors.New("dnscat2: invalid tunnel domain")
		}
	}
	return &Codec{Domain: domain}, nil
}

func ParseRecordTypes(value string) ([]uint16, error) {
	if strings.TrimSpace(value) == "" || strings.EqualFold(strings.TrimSpace(value), "ANY") {
		value = "TXT,CNAME,MX"
	}
	seen := make(map[uint16]bool)
	var result []uint16
	for _, item := range strings.Split(value, ",") {
		var recordType uint16
		switch strings.ToUpper(strings.TrimSpace(item)) {
		case "TXT":
			recordType = dns.TypeTXT
		case "CNAME":
			recordType = dns.TypeCNAME
		case "MX":
			recordType = dns.TypeMX
		case "A":
			recordType = dns.TypeA
		case "AAAA":
			recordType = dns.TypeAAAA
		default:
			return nil, fmt.Errorf("dnscat2: unsupported DNS record type %q", item)
		}
		if !seen[recordType] {
			seen[recordType] = true
			result = append(result, recordType)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("dnscat2: no DNS record types")
	}
	return result, nil
}

func (c *Codec) MaxPayload() int {
	limit := maxResponseBytes
	// Use the smallest upstream response allowance across selectable types.
	if c.Domain != "" {
		limit -= len(c.Domain) + 1
	} else {
		limit -= len(wildcardPrefix) + 1
	}
	for limit > 0 && len(c.EncodeQueryName(make([]byte, limit))) > 253 {
		limit--
	}
	return limit
}

func (c *Codec) EncodeQueryName(payload []byte) string {
	encoded := hex.EncodeToString(payload)
	labels := make([]string, 0, len(encoded)/63+2)
	if c.Domain == "" {
		labels = append(labels, wildcardPrefix)
	}
	for len(encoded) > 63 {
		labels = append(labels, encoded[:63])
		encoded = encoded[63:]
	}
	if encoded != "" {
		labels = append(labels, encoded)
	}
	if c.Domain != "" {
		labels = append(labels, c.Domain)
	}
	return dns.Fqdn(strings.Join(labels, "."))
}

func (c *Codec) BuildQuery(id uint16, recordType uint16, payload []byte) (*dns.Msg, error) {
	name := c.EncodeQueryName(payload)
	if len(name) > 254 {
		return nil, errors.New("dnscat2: encoded DNS name is too long")
	}
	message := new(dns.Msg)
	message.Id = id
	message.RecursionDesired = true
	message.Question = []dns.Question{{Name: name, Qtype: recordType, Qclass: dns.ClassINET}}
	// A responses carry many numbered records and can exceed legacy 512-byte
	// UDP DNS. Advertise an IPv6-safe UDP size to recursive resolvers.
	message.SetEdns0(1232, false)
	return message, nil
}

func (c *Codec) DecodeQuery(message *dns.Msg) ([]byte, error) {
	if message == nil || len(message.Question) != 1 {
		return nil, errors.New("dnscat2: expected exactly one DNS question")
	}
	question := message.Question[0]
	if question.Qclass != dns.ClassINET || !supportedType(question.Qtype) {
		return nil, errors.New("dnscat2: unsupported DNS question")
	}
	name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	var encoded string
	if c.Domain == "" {
		prefix := wildcardPrefix + "."
		if !strings.HasPrefix(name, prefix) {
			return nil, errors.New("dnscat2: missing dnscat prefix")
		}
		encoded = strings.TrimPrefix(name, prefix)
	} else {
		suffix := "." + c.Domain
		if !strings.HasSuffix(name, suffix) || len(name) <= len(suffix) {
			return nil, errors.New("dnscat2: unknown tunnel domain")
		}
		encoded = strings.TrimSuffix(name, suffix)
	}
	encoded = strings.ReplaceAll(encoded, ".", "")
	if encoded == "" || len(encoded)%2 != 0 {
		return nil, errors.New("dnscat2: invalid hexadecimal DNS name")
	}
	payload, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("dnscat2: invalid hexadecimal DNS payload")
	}
	return payload, nil
}

func (c *Codec) BuildResponse(query *dns.Msg, payload []byte) (*dns.Msg, error) {
	if len(payload) > c.MaxPayload() {
		return nil, errors.New("dnscat2: response exceeds DNS payload limit")
	}
	if len(query.Question) != 1 {
		return nil, errors.New("dnscat2: response requires one question")
	}
	question := query.Question[0]
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.RecursionAvailable = true
	if query.IsEdns0() != nil {
		response.SetEdns0(1232, false)
	}
	header := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET, Ttl: 60}

	switch question.Qtype {
	case dns.TypeTXT:
		response.Answer = []dns.RR{&dns.TXT{Hdr: header, Txt: []string{hex.EncodeToString(payload)}}}
	case dns.TypeCNAME:
		response.Answer = []dns.RR{&dns.CNAME{Hdr: header, Target: c.responseName(payload)}}
	case dns.TypeMX:
		response.Answer = []dns.RR{&dns.MX{Hdr: header, Preference: 10, Mx: c.responseName(payload)}}
	case dns.TypeA:
		chunks := chunkResponse(payload, 3)
		for index, chunk := range chunks {
			data := net.IPv4(byte(index), 0, 0, 0).To4()
			copy(data[1:], chunk)
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: data})
		}
	case dns.TypeAAAA:
		chunks := chunkResponse(payload, 15)
		for index, chunk := range chunks {
			data := make(net.IP, net.IPv6len)
			data[0] = byte(index)
			copy(data[1:], chunk)
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: data})
		}
	default:
		return nil, errors.New("dnscat2: unsupported response type")
	}
	return response, nil
}

func (c *Codec) DecodeResponse(response *dns.Msg, queryID uint16, recordType uint16) ([]byte, error) {
	if response == nil || response.Id != queryID || !response.Response || response.Truncated {
		return nil, errors.New("dnscat2: mismatched DNS response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dnscat2: DNS response code %s", dns.RcodeToString[response.Rcode])
	}
	var answers []dns.RR
	for _, answer := range response.Answer {
		if answer.Header().Rrtype == recordType {
			answers = append(answers, answer)
		}
	}
	if len(answers) == 0 {
		return nil, errors.New("dnscat2: empty DNS answer")
	}
	switch recordType {
	case dns.TypeTXT:
		if len(answers) != 1 {
			return nil, errors.New("dnscat2: ambiguous TXT answer")
		}
		value := strings.Join(answers[0].(*dns.TXT).Txt, "")
		return decodeHex(value)
	case dns.TypeCNAME, dns.TypeMX:
		if len(answers) != 1 {
			return nil, errors.New("dnscat2: ambiguous name answer")
		}
		var name string
		if recordType == dns.TypeCNAME {
			name = answers[0].(*dns.CNAME).Target
		} else {
			name = answers[0].(*dns.MX).Mx
		}
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		var encoded string
		if c.Domain == "" {
			if name == wildcardPrefix {
				return []byte{}, nil
			}
			if !strings.HasPrefix(name, wildcardPrefix+".") {
				return nil, errors.New("dnscat2: wrong response prefix")
			}
			encoded = strings.TrimPrefix(name, wildcardPrefix+".")
		} else {
			if name == c.Domain {
				return []byte{}, nil
			}
			if !strings.HasSuffix(name, "."+c.Domain) {
				return nil, errors.New("dnscat2: wrong response domain")
			}
			encoded = strings.TrimSuffix(name, "."+c.Domain)
		}
		return decodeHex(strings.ReplaceAll(encoded, ".", ""))
	case dns.TypeA:
		return decodeAddressAnswers(answers, net.IPv4len, 3)
	case dns.TypeAAAA:
		return decodeAddressAnswers(answers, net.IPv6len, 15)
	}
	return nil, errors.New("dnscat2: unsupported response type")
}

func (c *Codec) responseName(payload []byte) string {
	if len(payload) == 0 {
		if c.Domain == "" {
			return wildcardPrefix + "."
		}
		return c.Domain + "."
	}
	return c.EncodeQueryName(payload)
}

func decodeHex(value string) ([]byte, error) {
	if value == "" {
		return []byte{}, nil
	}
	if len(value)%2 != 0 {
		return nil, errors.New("dnscat2: odd hexadecimal response")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("dnscat2: invalid hexadecimal response")
	}
	return decoded, nil
}

func chunkResponse(payload []byte, size int) [][]byte {
	data := append([]byte{byte(len(payload))}, payload...)
	var chunks [][]byte
	for len(data) > 0 {
		length := min(size, len(data))
		chunk := append([]byte(nil), data[:length]...)
		data = data[length:]
		for len(chunk) < size {
			chunk = append(chunk, 0xff)
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}

func decodeAddressAnswers(answers []dns.RR, addressLength, chunkSize int) ([]byte, error) {
	type numberedChunk struct {
		sequence byte
		data     []byte
	}
	chunks := make([]numberedChunk, 0, len(answers))
	seen := make(map[byte]bool)
	for _, answer := range answers {
		var address net.IP
		if addressLength == net.IPv4len {
			address = answer.(*dns.A).A.To4()
		} else {
			address = answer.(*dns.AAAA).AAAA.To16()
		}
		if len(address) != addressLength {
			return nil, errors.New("dnscat2: invalid address answer")
		}
		if seen[address[0]] {
			return nil, errors.New("dnscat2: duplicate answer sequence")
		}
		seen[address[0]] = true
		chunks = append(chunks, numberedChunk{sequence: address[0], data: address[1:]})
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].sequence < chunks[j].sequence })
	var data bytes.Buffer
	for _, chunk := range chunks {
		data.Write(chunk.data[:chunkSize])
	}
	result := data.Bytes()
	if len(result) == 0 || int(result[0]) > len(result)-1 {
		return nil, errors.New("dnscat2: invalid address answer length")
	}
	return result[1 : int(result[0])+1], nil
}

func supportedType(recordType uint16) bool {
	switch recordType {
	case dns.TypeTXT, dns.TypeCNAME, dns.TypeMX, dns.TypeA, dns.TypeAAAA:
		return true
	}
	return false
}
