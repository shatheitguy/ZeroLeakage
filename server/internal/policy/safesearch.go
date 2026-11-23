package policy

import "strings"

// SafeSearch forces the "safe" version of search engines and YouTube by answering their hostnames
// with a CNAME to the engine's own restricted endpoint (the documented DNS method for each engine).
type SafeSearch struct {
	Google     bool   `json:"google"`
	Bing       bool   `json:"bing"`
	DuckDuckGo bool   `json:"duckduckgo"`
	YouTube    string `json:"youtube"` // "off" | "moderate" | "strict"
}

const (
	googleSafe   = "forcesafesearch.google.com"
	bingSafe     = "strict.bing.com"
	ddgSafe      = "safe.duckduckgo.com"
	ytStrict     = "restrict.youtube.com"
	ytModerate   = "restrictmoderate.youtube.com"
	YouTubeOff   = "off"
	YouTubeMod   = "moderate"
	YouTubeStrct = "strict"
)

func ytLevel(v string) int {
	switch v {
	case YouTubeStrct:
		return 2
	case YouTubeMod:
		return 1
	}
	return 0
}

// Normalize fixes unknown YouTube values.
func (s SafeSearch) Normalize() SafeSearch {
	switch s.YouTube {
	case YouTubeMod, YouTubeStrct:
	default:
		s.YouTube = YouTubeOff
	}
	return s
}

// Stricter merges two settings: anything on in either stays on, YouTube takes the stricter level.
func (s SafeSearch) Stricter(o SafeSearch) SafeSearch {
	out := SafeSearch{Google: s.Google || o.Google, Bing: s.Bing || o.Bing, DuckDuckGo: s.DuckDuckGo || o.DuckDuckGo, YouTube: s.Normalize().YouTube}
	if ytLevel(o.YouTube) > ytLevel(out.YouTube) {
		out.YouTube = o.Normalize().YouTube
	}
	return out
}

// Any reports whether anything is enforced.
func (s SafeSearch) Any() bool { return s.Google || s.Bing || s.DuckDuckGo || ytLevel(s.YouTube) > 0 }

var (
	googleHosts = map[string]bool{}
	bingHosts   = map[string]bool{"bing.com": true, "www.bing.com": true, "cn.bing.com": true}
	ddgHosts    = map[string]bool{"duckduckgo.com": true, "www.duckduckgo.com": true, "start.duckduckgo.com": true, "html.duckduckgo.com": true, "lite.duckduckgo.com": true}
	ytHosts     = map[string]bool{"www.youtube.com": true, "m.youtube.com": true, "youtubei.googleapis.com": true, "youtube.googleapis.com": true, "www.youtube-nocookie.com": true}
)

// Google search lives on google.<tld> for every country domain; only the search hosts themselves
// (google.X and www.google.X) are rewritten, never mail.google.com and friends.
var googleTLDs = strings.Fields(`com ac ad ae al am as at az ba be bf bg bi bj bs bt by ca cat cd cf cg ch ci cl cm cn
co.ao co.bw co.ck co.cr co.id co.il co.in co.jp co.ke co.kr co.ls co.ma co.mz co.nz co.th co.tz co.ug co.uk co.uz co.ve co.vi co.za co.zm co.zw
com.af com.ag com.ai com.ar com.au com.bd com.bh com.bn com.bo com.br com.bz com.co com.cu com.cy com.do com.ec com.eg com.et com.fj com.gh com.gi com.gt
com.hk com.jm com.kh com.kw com.lb com.ly com.mm com.mt com.mx com.my com.na com.ng com.ni com.np com.om com.pa com.pe com.pg com.ph com.pk com.pr com.py
com.qa com.sa com.sb com.sg com.sl com.sv com.tj com.tr com.tw com.ua com.uy com.vc com.vn cv cz de dj dk dm dz ee es fi fm fr ga ge gg gl gm gr gy hn hr ht hu
ie im iq is it je jo kg ki kz la li lk lt lu lv md me mg mk ml mn ms mu mv mw ne nl no nr nu pl pn ps pt ro rs ru rw sc se sh si sk sm sn so sr st td tg tl tm tn to tt vg vu ws`)

func init() {
	for _, t := range googleTLDs {
		googleHosts["google."+t] = true
		googleHosts["www.google."+t] = true
	}
}

// SafeTarget returns the restricted hostname to answer for domain under s ("" when not rewritten).
func SafeTarget(domain string, s SafeSearch) (target, engine string) {
	switch {
	case s.Google && googleHosts[domain]:
		return googleSafe, "Google"
	case s.Bing && bingHosts[domain]:
		return bingSafe, "Bing"
	case s.DuckDuckGo && ddgHosts[domain]:
		return ddgSafe, "DuckDuckGo"
	case ytHosts[domain]:
		switch s.YouTube {
		case YouTubeStrct:
			return ytStrict, "YouTube"
		case YouTubeMod:
			return ytModerate, "YouTube"
		}
	}
	return "", ""
}
