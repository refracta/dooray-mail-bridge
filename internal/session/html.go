package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type pageForm struct {
	Action string
	Method string
	Values url.Values
}
type loginPage struct {
	Inputs   map[string]string
	Forms    []pageForm
	NextData []byte
	LinkURL  string
}

var linkURLPattern = regexp.MustCompile(`(?:var|let|const)\s+linkUrl\s*=\s*["']([^"'\r\n]+)["']`)

func parseLoginPage(body []byte) (loginPage, error) {
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return loginPage{}, errors.New("invalid login HTML")
	}
	out := loginPage{Inputs: make(map[string]string)}
	var walk func(*html.Node, *pageForm)
	walk = func(n *html.Node, form *pageForm) {
		if n.Type == html.ElementNode {
			attrs := map[string]string{}
			for _, a := range n.Attr {
				attrs[a.Key] = a.Val
			}
			if n.Data == "form" {
				f := pageForm{Action: attrs["action"], Method: strings.ToUpper(attrs["method"]), Values: make(url.Values)}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, &f)
				}
				out.Forms = append(out.Forms, f)
				return
			}
			if n.Data == "input" {
				key := attrs["id"]
				if key == "" {
					key = attrs["name"]
				}
				if key != "" {
					out.Inputs[key] = attrs["value"]
				}
				_, disabled := attrs["disabled"]
				if form != nil && attrs["name"] != "" && !disabled && !strings.EqualFold(attrs["type"], "submit") && !strings.EqualFold(attrs["type"], "button") {
					form.Values.Add(attrs["name"], attrs["value"])
				}
			}
			if n.Data == "script" && attrs["id"] == "__NEXT_DATA__" && n.FirstChild != nil {
				out.NextData = []byte(n.FirstChild.Data)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, form)
		}
	}
	walk(root, nil)
	if match := linkURLPattern.FindSubmatch(body); len(match) > 1 {
		out.LinkURL = string(match[1])
	}
	return out, nil
}

func (p loginPage) samlLoginURL() (string, error) {
	var data struct {
		Props struct {
			PageProps struct {
				Buttons []struct {
					URL string `json:"url"`
				} `json:"multiLoginButtons"`
			} `json:"pageProps"`
		} `json:"props"`
	}
	if err := json.Unmarshal(p.NextData, &data); err != nil {
		return "", errors.New("Dooray login page did not expose its SAML login option")
	}
	for _, b := range data.Props.PageProps.Buttons {
		u, err := url.Parse(b.URL)
		if err == nil && u.Path == "/idp/login/saml" {
			return b.URL, nil
		}
	}
	return "", errors.New("Dooray tenant has no supported SAML login option")
}
