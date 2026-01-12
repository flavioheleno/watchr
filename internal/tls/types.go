package tls

import (
	"time"
)

type Response struct {
	Host           string        `json:"host"`
	Port           string        `json:"port"`
	TLSVersion     string        `json:"tlsVersion"`
	CipherSuite    string        `json:"cipherSuite"`
	Certificates   []Certificate `json:"certificates"`
	VerifiedChains [][]int       `json:"verifiedChains,omitempty"`
}

type Certificate struct {
	Subject            Subject   `json:"subject"`
	Issuer             Subject   `json:"issuer"`
	SerialNumber       string    `json:"serialNumber"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string    `json:"publicKeyAlgorithm"`
	PublicKeySize      int       `json:"publicKeySize"`
	DNSNames           []string  `json:"dnsNames,omitempty"`
	IsCA               bool      `json:"isCA"`
}

type Subject struct {
	CommonName         string   `json:"commonName"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
}

type TestResult struct {
	Host              string              `json:"host"`
	Port              string              `json:"port"`
	SupportedVersions map[string]bool     `json:"supportedVersions"`
	CipherSuites      map[string][]string `json:"cipherSuites,omitempty"`
	Vulnerabilities   []string            `json:"vulnerabilities,omitempty"`
	PreferredVersion  string              `json:"preferredVersion,omitempty"`
	PreferredCipher   string              `json:"preferredCipher,omitempty"`
}
