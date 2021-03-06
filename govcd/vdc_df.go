package govcd

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/lmicke/go-vcloud-director/v2/types/v56"
)

type DFW struct {
	Section *DFWSection
	Client  *Client
	Etag    string
}

func NewDFW(cli *Client) *DFW {
	return &DFW{
		Section: &DFWSection{},
		Client:  cli,
		Etag:    "Test",
	}
}

func urnToUID(urn string) string {

	if isUrn(urn) {
		uid := strings.TrimPrefix(urn, "urn:vcloud:vdc:")
		return uid
	}
	return urn
}

func (dfw *DFW) EnableDistributedFirewall(VdcID string) (string, error) {

	base := dfw.Client.VCDHREF
	ID := urnToUID(VdcID)
	add, err := url.Parse(types.DFWOn + ID + "?append=true")
	if err != nil {
		return "", fmt.Errorf("Error building url for DFW activation: %s", err)
	}
	dfwURL := base.ResolveReference(add)
	log.Printf("[DEBUG] Enable Distributed Firewall URL is: %s", dfwURL.String())

	resp, err := dfw.Client.ExecuteRequest(dfwURL.String(), http.MethodPost, "", "error enabling dfw: %s", nil, nil)
	//resp, err := dfw.Client.ExecuteParamRequestWithCustomError()
	log.Printf("Response for Enabling: %v", resp)
	if err != nil {
		return dfwURL.String(), err
	}
	return dfwURL.String(), nil
}

func (dfw *DFW) CheckDistributedFirewall(VdcID string) (bool, error) {
	base := dfw.Client.VCDHREF
	ID := urnToUID(VdcID)
	add, err := url.Parse(types.DFWRequest + ID)
	if err != nil {
		return false, fmt.Errorf("Error building url for DFW check: %s", err)
	}
	dfwURL := base.ResolveReference(add)
	log.Printf("[DEBUG] Check Distributed Firewall URL is: %s", dfwURL.String())
	resp, err := dfw.Client.ExecuteRequest(dfwURL.String(), http.MethodGet, "", "error reaching dfwURL: %s", nil, dfw.Section)
	log.Printf("Response for Check Firewall: %v", resp)
	if err != nil {
		return false, err
	}
	if (resp.StatusCode == 404) || (resp.StatusCode == 400) {
		return false, nil
	}
	if resp.StatusCode == 200 {
		header := resp.Header
		//dfw.Etag = header["ETag"][0]
		dfw.Etag = header.Get("ETag")
		log.Printf("[DEBUG] Etag after Check Firewall: %s", dfw.Etag)
		return true, nil
	}

	return false, fmt.Errorf("Unexptected Status Code %s", resp.Status)
}

func (dfw *DFW) DeleteDistributedFirewall(VdcID string) error {
	base := dfw.Client.VCDHREF
	ID := urnToUID(VdcID)
	add, err := url.Parse(types.DFWOn + ID)
	if err != nil {
		return fmt.Errorf("Error building url for DFW Delete: %s", err)
	}
	dfwURL := base.ResolveReference(add)
	log.Printf("[DEBUG] Delete Distributed Firewall URL is: %s", dfwURL.String())
	resp, err := dfw.Client.ExecuteRequest(dfwURL.String(), http.MethodDelete, "", "error reaching dfwURL: %s", nil, nil)
	log.Printf("[DEBUG] Response for Delete Firewall: %v", resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != 204 {
		return fmt.Errorf("Deleting Firewall was not successfull, API Response is:  %s", resp.Status)
	}
	return nil
}

func (dfw *DFW) UpdateDistributedFirewall(VdcID string) error {
	base := dfw.Client.VCDHREF
	ID := urnToUID(VdcID)
	add, err := url.Parse(types.DFWRequest + ID)
	if err != nil {
		return fmt.Errorf("Error building url for DFW Delete: %s", err)
	}
	dfwURL := base.ResolveReference(add)
	log.Printf("[DEBUG] Update Distributed Firewall URL is: %s", dfwURL.String())
	// Build default Change moved to terraform resource
	//dfw.Section.Rules[0].Name = "Default Deny"
	//dfw.Section.Rules[0].Action = "deny"
	log.Printf("[DEBUG] Etag is: %s", dfw.Etag)
	resp, err := dfw.Client.ExecuteRequestWithCustomHeader(dfwURL.String(), http.MethodPut, "", "error reaching dfwURL: %s", dfw.Etag, dfw.Section, dfw.Section)
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[DEBUG] Response for Update  Firewall: %s", string(body))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Updating Firewall was not successfull, API Response is:  %s", resp.Status)
	}
	return nil
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
	Name          string        `xml:"name"`          //optional
	Action        string        `xml:"action"`        //must allow, deny
	AppliedToList DFWAppliedTo  `xml:"appliedToList"` //Kandidaten ORG_VDC, VMs, Netzwerke, Security Groups, Edge
	Sources       *Sources      `xml:"sources,omitempty"`
	Destinations  *Destinations `xml:"destinations,omitempty"`
	Services      *Services     `xml:"services,omitempty"`
	SectionID     int           `xml:"sectionId"`
	Direction     string        `xml:"direction"`
	PacketType    string        `xml:"packetType"`
	Tag           string        `xml:"tag"`
	ID            int           `xml:"id,attr"`
	Disabled      bool          `xml:"disabled,attr"`
	Logged        bool          `xml:"logged,attr"`
}

type DFWApplied struct {
	Name    string `xml:"name,omitempty"`
	Value   string `xml:"value"`
	Type    string `xml:"type"`
	IsValid bool   `xml:"isValid,omitempty"`
}

type DFWAppliedTo struct {
	Applied []DFWApplied `xml:"appliedTo"`
}

//Add Sources and Destinations

type Sources struct {
	Excluded string       `xml:"excluded,attr"`
	Source   []DFWApplied `xml:"source"`
}

type Destinations struct {
	Excluded    string       `xml:"excluded,attr"`
	Destination []DFWApplied `xml:"destination"`
}

// Add Service Struct
type Services struct {
	Service []DFWApplied `xml:"service"`
}

// Update Request with Custom Etag Header:

func (cli *Client) NewRequestWithCustomHeader(params map[string]string, notEncodedParams map[string]string, method string, reqUrl url.URL, body io.Reader, etag string) *http.Request {
	headers := make(http.Header)
	headers.Add("If-Match", etag)
	headers.Add("Accept", "application/xml;charset=UTF-8")
	headers.Add("Content-Type", "application/xml;charset=UTF-8")
	return cli.newRequest(params, nil, method, reqUrl, body, cli.APIVersion, headers)

}

func (cli *Client) ExecuteRequestWithCustomHeader(pathURL, requestType, contentType, errorMessage, etag string, payload, out interface{}) (*http.Response, error) {
	if !isMessageWithPlaceHolder(errorMessage) {
		return &http.Response{}, fmt.Errorf("error message has to include place holder for error")
	}

	url, _ := url.ParseRequestURI(pathURL)

	var req *http.Request
	switch requestType {
	case http.MethodPost, http.MethodPut:

		marshaledXml, err := xml.MarshalIndent(payload, "  ", "    ")
		if err != nil {
			return &http.Response{}, fmt.Errorf("error marshalling xml data %v", err)
		}
		body := bytes.NewBufferString(xml.Header + string(marshaledXml))

		req = cli.NewRequestWithCustomHeader(map[string]string{}, nil, requestType, *url, body, etag)

	default:
		req = cli.NewRequestWithCustomHeader(map[string]string{}, nil, requestType, *url, nil, etag)
	}

	if contentType != "" {
		req.Header.Add("Content-Type", contentType)
	}

	setHttpUserAgent(cli.UserAgent, req)

	resp, err := cli.Http.Do(req)
	if err != nil {
		return resp, fmt.Errorf(errorMessage, err)
	}

	nsxError := types.NSXError{}
	if resp.StatusCode == 400 {
		if err = decodeBody(types.BodyTypeXML, resp, nsxError); err != nil {
			return resp, fmt.Errorf("error decoding response: %s", err)
		}
		return resp, nsxError
	}

	if err = decodeBody(types.BodyTypeXML, resp, out); err != nil {
		return resp, fmt.Errorf("error decoding response: %s", err)
	}

	err = resp.Body.Close()
	if err != nil {
		return resp, fmt.Errorf("error closing response body: %s", err)
	}

	// The request was successful
	return resp, nil
}
