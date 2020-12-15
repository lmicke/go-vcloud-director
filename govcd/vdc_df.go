package govcd

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lmicke/go-vcloud-director/v2/types/v56"
)

type DFW struct {
	Section *DFWSection
	client  *Client
}

func NewDFW(cli *Client) *DFW {
	return &DFW{
		Section: new(DFWSection),
		client:  cli,
	}
}

func (dfw *DFW) EnableDistributedFirewall(VdcID string) error {
	base := dfw.client.VCDHREF
	add, err := url.Parse(types.DFWOn + VdcID)
	if err != nil {
		return fmt.Errorf("Error building url for DFW activation: %s", err)
	}
	dfwURL := base.ResolveReference(add)

	_, err = dfw.client.ExecuteRequest(dfwURL.String(), http.MethodPost, "", "error enabling dfw: %s", nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (dfw *DFW) CheckDistributedFirewall(VdcId string) (bool, error) {
	base := dfw.client.VCDHREF
	add, err := url.Parse(types.DFWRequest + VdcId)
	if err != nil {
		return false, fmt.Errorf("Error building url for DFW check: %s", err)
	}
	dfwURL := base.ResolveReference(add)

	resp, err := dfw.client.ExecuteRequest(dfwURL.String(), http.MethodGet, "", "error enabling dfw: %s", dfw.Section, nil)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode == 200 {
		return true, nil
	}

	return false, fmt.Errorf("Unexptected Status Code %s", resp.Status)
}

type DFWSection struct {
	XMLName          xml.Name  `xml:"section"`
	Rules            []DFWRule `xml:"rule"`
	ID               int       `xml:"id,attr"`
	Name             string    `xml:"name,attr"`
	GenerationNumber string    `xml:"generationNumber,attr"`
	Timestamp        string    `xml:"timestamp,attr"`
	TCPStrict        bool      `xml:"tcpStrict,attr"`
	Stateless        bool      `xml:"stateless,attr"`
	UseSid           bool      `xml:"useSid,attr"`
	Type             string    `xml:"type,attr"`
}

type DFWRule struct {
	Name          string         `xml:"name"`
	Action        string         `xml:"action"`
	AppliedToList []DFWAppliedTo `xml:"appliedToList"`
	SectionID     int            `xml:"sectionId"`
	Direction     string         `xml:"direction"`
	PacketType    string         `xml:"packetType"`
	Tag           string         `xml:"tag"`
	ID            int            `xml:"id,attr"`
	Disabled      bool           `xml:"disabled,attr"`
	Logged        bool           `xml:"logged,attr"`
}

type DFWApplied struct {
	Name    string `xml:"name"`
	Value   string `xml:"value"`
	Type    string `xml:"type"`
	IsValid bool   `xml:"isValid"`
}

type DFWAppliedTo struct {
	ID DFWApplied `xml:"appliedTo"`
}
