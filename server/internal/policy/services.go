package policy

import (
	"math/bits"
	"strings"
)

// Service is a one-click blockable app or website: a set of domains (each covers its subdomains).
type Service struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Domains []string `json:"domains"`
}

// Services is the built-in catalog. Order matters: a service's position is its bit in a policy mask
// (at most 64 services). Domains are the ones the apps and websites actually use, including CDNs that
// only serve that service; shared infrastructure (generic CDNs, app stores) is left out on purpose.
var Services = []Service{
	{"youtube", "YouTube", "Video", []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtube.googleapis.com", "yt.be", "youtubekids.com", "youtube-ui.l.google.com", "wide-youtube.l.google.com", "yt3.ggpht.com", "yt4.ggpht.com", "youtubeeducation.com"}},
	{"tiktok", "TikTok", "Social", []string{"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokv.eu", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokcdn-eu.com", "tiktokw.us", "tiktokw.eu", "tiktok.us", "tiktokd.net", "tiktokd.org", "ttwstatic.com", "ttlivecdn.com", "byteoversea.com", "byteoversea.net", "ibytedtos.com", "ibyteimg.com", "ipstatp.com", "muscdn.com", "musical.ly", "tik-tokapi.com", "tiktok-row.net", "tiktok-row.org", "bytegecko-i18n.com"}},
	{"facebook", "Facebook", "Social", []string{"facebook.com", "facebook.net", "fb.com", "fb.me", "fb.gg", "fbcdn.net", "fbsbx.com", "fbpigeon.com", "facebook.de", "facebook.fr", "accountkit.com", "fbwat.ch"}},
	{"instagram", "Instagram", "Social", []string{"instagram.com", "cdninstagram.com", "ig.me", "instagr.am", "igcdn.com", "igsonar.com", "instagram.net"}},
	{"whatsapp", "WhatsApp", "Messaging", []string{"whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.biz", "whatsapp.info", "whatsapp.org", "whatsapp.tv"}},
	{"messenger", "Messenger", "Messaging", []string{"messenger.com", "m.me", "msngr.com", "edge-mqtt.facebook.com", "mqtt-mini.facebook.com"}},
	{"snapchat", "Snapchat", "Social", []string{"snapchat.com", "snap.com", "sc-cdn.net", "sc-static.net", "sc-prod.net", "snap-dev.net", "snapkit.co", "snapads.com", "snapchat.net", "bitmoji.com", "feelinsonice-hrd.appspot.com", "feelinsonice.appspot.com"}},
	{"twitter", "X (Twitter)", "Social", []string{"x.com", "twitter.com", "twimg.com", "t.co", "twttr.com", "twitter.co", "twitter.biz", "twitpic.com", "pscp.tv", "periscope.tv", "ads-twitter.com", "tweetdeck.com", "twitterinc.com", "twitterstat.us", "twtrdns.net"}},
	{"reddit", "Reddit", "Social", []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "reddituploads.com", "redditspace.com", "redditinc.com", "reddit.map.fastly.net"}},
	{"discord", "Discord", "Messaging", []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com", "discord.co", "discord.new", "discord.gift", "discord.gifts", "discordstatus.com", "dis.gd", "discord.dev"}},
	{"telegram", "Telegram", "Messaging", []string{"telegram.org", "telegram.me", "t.me", "telegram.dog", "telegram.space", "telegra.ph", "tdesktop.com", "telesco.pe", "cdn-telegram.org", "graph.org", "tg.dev", "telegram-cdn.org"}},
	{"netflix", "Netflix", "Video", []string{"netflix.com", "netflix.net", "nflxext.com", "nflximg.com", "nflximg.net", "nflxso.net", "nflxvideo.net", "nflxsearch.net", "netflixdnstest1.com", "netflixdnstest2.com"}},
	{"twitch", "Twitch", "Video", []string{"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "ext-twitch.tv", "twitchapps.com", "live-video.net", "twitch.a2z.com", "twitchcdn-shadow.net"}},
	{"spotify", "Spotify", "Music", []string{"spotify.com", "scdn.co", "spotifycdn.com", "spotifycdn.net", "spotilocal.com", "spoti.fi", "spotify.design", "pscdn.co", "byspotify.com", "tospotify.com", "spotifycharts.com", "spotify.link", "audio-ak-spotify-com.akamaized.net", "heads-ak-spotify-com.akamaized.net"}},
	{"pinterest", "Pinterest", "Social", []string{"pinterest.com", "pinimg.com", "pin.it", "pinterest.net", "pinterest.co.uk", "pinterest.ca", "pinterest.de", "pinterest.fr", "pinterest.es", "pinterest.it", "pinterest.jp", "pinterest.com.au", "pinterest.com.mx", "pinterest.nz", "pinterest.ch", "pinterest.at", "pinterest.ie", "pinterest.pt", "pinterest.se", "pinterest.dk", "pinterest.ph", "pinterest.cl"}},
	{"tinder", "Tinder", "Dating", []string{"tinder.com", "gotinder.com", "tindersparks.com", "tinderops.net"}},
	{"roblox", "Roblox", "Gaming", []string{"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com", "roblox.net", "rbxinfra.com", "roblox.qq.com", "rbxtrk.com"}},
	{"epic", "Fortnite / Epic Games", "Gaming", []string{"epicgames.com", "epicgames.dev", "epicgames.net", "fortnite.com", "unrealengine.com", "epicgamescdn.com", "fortnitepartybuilder.com"}},
	{"steam", "Steam", "Gaming", []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com", "steamusercontent.com", "steam-chat.com", "valvesoftware.com", "steamcdn-a.akamaihd.net", "steam.tv", "s.team"}},
	{"primevideo", "Amazon Prime Video", "Video", []string{"primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net", "atv-ps.amazon.com", "atv-ps-eu.amazon.com", "atv-ps-fe.amazon.com", "atv-ext.amazon.com", "atv-ext-eu.amazon.com", "atv-ext-fe.amazon.com", "primevideo.amazon.com"}},
	{"disneyplus", "Disney+", "Video", []string{"disneyplus.com", "disney-plus.net", "disneystreaming.com", "dssott.com", "bamgrid.com", "dssedge.com", "disneynow.com", "starplus.com"}},
	{"tumblr", "Tumblr", "Social", []string{"tumblr.com", "tmblr.co", "tumblr.net"}},
	{"vimeo", "Vimeo", "Video", []string{"vimeo.com", "vimeocdn.com", "vimeo.tv", "vhx.tv", "vimeows.com"}},
	{"dailymotion", "Dailymotion", "Video", []string{"dailymotion.com", "dmcdn.net", "dm-event.net", "dmxleo.com", "dai.ly"}},
	{"9gag", "9GAG", "Social", []string{"9gag.com", "9cache.com", "9gag-cdn.com"}},
	{"imgur", "Imgur", "Social", []string{"imgur.com", "imgur.io"}},
	{"threads", "Threads", "Social", []string{"threads.net", "threads.com"}},
	{"kick", "Kick", "Video", []string{"kick.com"}},
}

var (
	serviceIndex = map[string]uint64{}
	serviceByID  = map[string]int{}
)

func init() {
	if len(Services) > 64 {
		panic("policy: more than 64 services")
	}
	for i, s := range Services {
		serviceByID[s.ID] = i
		for _, d := range s.Domains {
			serviceIndex[strings.ToLower(d)] |= 1 << i
		}
	}
}

// ServiceMask returns the bitmask for service ids (unknown ids are ignored).
func ServiceMask(ids []string) uint64 {
	var m uint64
	for _, id := range ids {
		if i, ok := serviceByID[id]; ok {
			m |= 1 << i
		}
	}
	return m
}

// KnownService reports whether id is in the catalog.
func KnownService(id string) bool { _, ok := serviceByID[id]; return ok }

// ServiceIDs returns the ids in a mask, in catalog order.
func ServiceIDs(mask uint64) []string {
	out := []string{}
	for mask != 0 {
		i := bits.TrailingZeros64(mask)
		out = append(out, Services[i].ID)
		mask &^= 1 << i
	}
	return out
}

// LookupServices returns the mask of every service the domain (or a parent) belongs to. No allocation.
func LookupServices(domain string) uint64 {
	var m uint64
	d := domain
	for {
		m |= serviceIndex[d]
		dot := strings.IndexByte(d, '.')
		if dot < 0 || dot == len(d)-1 {
			return m
		}
		d = d[dot+1:]
		if strings.IndexByte(d, '.') < 0 {
			return m
		}
	}
}

// FirstService returns the first service in mask (ok=false for an empty mask).
func FirstService(mask uint64) (Service, bool) {
	if mask == 0 {
		return Service{}, false
	}
	return Services[bits.TrailingZeros64(mask)], true
}

// ServiceByID returns a service from the catalog.
func ServiceByID(id string) (Service, bool) {
	if i, ok := serviceByID[id]; ok {
		return Services[i], true
	}
	return Service{}, false
}
