package rdap

import "time"

type Response struct {
	Handle      string       `json:"handle"`
	LDHName     string       `json:"ldhName"`
	Status      []string     `json:"status"`
	Entities    []Entity     `json:"entities"`
	Events      []Event      `json:"events"`
	Links       []Link       `json:"links"`
	Nameservers []Nameserver `json:"nameservers"`
	SecureDNS   *SecureDNS   `json:"secureDNS,omitempty"`
}

type Entity struct {
	Handle     string        `json:"handle"`
	Roles      []string      `json:"roles"`
	VCardArray []interface{} `json:"vcardArray,omitempty"`
}

type Event struct {
	EventAction string    `json:"eventAction"`
	EventDate   time.Time `json:"eventDate"`
}

type Link struct {
	Value string `json:"value"`
	Rel   string `json:"rel"`
	Href  string `json:"href"`
	Type  string `json:"type"`
}

type Nameserver struct {
	LDHName         string `json:"ldhName"`
	ObjectClassName string `json:"objectClassName"`
}

type SecureDNS struct {
	DelegationSigned bool `json:"delegationSigned"`
}
