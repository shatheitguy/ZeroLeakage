package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/shatheitguy/ZeroLeakage/server/internal/policy"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

// adminAndUser sets up an admin plus a normal user "sam" created by the admin.
func adminAndUser(t *testing.T) (*client, *client, string, int64) {
	srv := newServer(t)
	admin := newClient(t, srv.URL)
	if code := admin.do("POST", "/api/v1/auth/setup", map[string]string{"username": "admin", "password": "correct horse battery"}, nil, true); code != 200 {
		t.Fatalf("setup: %d", code)
	}
	var u store.User
	if code := admin.do("POST", "/api/v1/users", map[string]any{"username": "sam", "password": "sam's long password"}, &u, true); code != 201 {
		t.Fatalf("create user: %d", code)
	}
	user := newClient(t, srv.URL)
	if code := user.do("POST", "/api/v1/auth/login", map[string]string{"username": "sam", "password": "sam's long password"}, nil, true); code != 200 {
		t.Fatalf("user login: %d", code)
	}
	return admin, user, srv.URL, u.ID
}

type linkResp struct {
	Token  string `json:"token"`
	Device struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		DoHURL string `json:"dohUrl"`
	} `json:"device"`
	Server struct {
		Name string `json:"name"`
	} `json:"server"`
	Username string `json:"username"`
}

func TestPairingAndPolicySync(t *testing.T) {
	admin, user, base, uid := adminAndUser(t)

	// network baseline: TikTok blocked, a network block rule, Google SafeSearch
	net := policy.DefaultNetwork()
	net.Services = []string{"tiktok"}
	net.SafeSearch.Google = true
	if code := admin.do("PUT", "/api/v1/policy?scope=default", net, nil, true); code != 200 {
		t.Fatalf("network policy: %d", code)
	}
	admin.do("POST", "/api/v1/rules?scope=default", map[string]string{"kind": "block", "domain": "netblock.example"}, nil, true)
	// users can't change the network policy
	if code := user.do("PUT", "/api/v1/policy?scope=default", net, nil, true); code != 403 {
		t.Fatalf("user changed network policy: %d", code)
	}

	// pairing code: needs CSRF, one-time, owned by the user
	if code := user.do("POST", "/api/v1/devices/pair-code", map[string]string{"name": "Sam's phone"}, nil, false); code != 403 {
		t.Fatalf("pair-code without CSRF header: %d", code)
	}
	var pc struct {
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	user.do("POST", "/api/v1/devices/pair-code", map[string]string{"name": "Sam's phone"}, &pc, true)
	if len(pc.Code) != 12 || !strings.HasPrefix(pc.Code, "ZL-") || pc.ExpiresAt == 0 {
		t.Fatalf("code: %+v", pc)
	}
	anon := newClient(t, base)
	if code := anon.do("POST", "/api/v1/devices/pair", map[string]string{"code": "ZL-AAAA-AAAA", "deviceName": "x"}, nil, false); code != 401 {
		t.Fatalf("bad code: %d", code)
	}
	var phone linkResp
	if code := anon.do("POST", "/api/v1/devices/pair", map[string]string{"code": strings.ToLower(pc.Code), "deviceName": "Pixel", "platform": "android"}, &phone, false); code != 201 {
		t.Fatalf("pair: %d", code)
	}
	if phone.Token == "" || phone.Device.Name != "Sam's phone" || phone.Username != "sam" || phone.Server.Name == "" || !strings.HasSuffix(phone.Device.DoHURL, phone.Device.ID) {
		t.Fatalf("pair response: %+v", phone)
	}
	if code := anon.do("POST", "/api/v1/devices/pair", map[string]string{"code": pc.Code, "deviceName": "again"}, nil, false); code != 401 {
		t.Fatalf("a code must work only once: %d", code)
	}
	// password linking with platform
	var laptop linkResp
	if code := anon.do("POST", "/api/v1/devices/link", map[string]string{"username": "sam", "password": "sam's long password", "deviceName": "Laptop", "platform": "windows"}, &laptop, false); code != 201 || laptop.Username != "sam" {
		t.Fatalf("password link: %d %+v", code, laptop)
	}

	// the phone pushes rules (app format) and its own extras
	p := newClient(t, base)
	p.auth = phone.Token
	var put map[string]any
	p.do("PUT", "/api/v1/sync", map[string]any{
		"rules": []map[string]string{
			{"domain": "netblock.example", "action": "allow", "op": "add"},
			{"domain": "mine.example", "action": "block", "op": "add"},
			{"domain": "gone.example", "action": "block", "op": "remove"},
		},
		"userPolicy": map[string]any{"lists": []string{"hagezi_pro"}, "customLists": []map[string]string{{"name": "Mine", "url": "https://example.com/list.txt"}}, "services": []string{"youtube", "tiktok"}},
	}, &put, false)
	if put["userPolicyApplied"] != true || put["policyVersion"] == "" {
		t.Fatalf("sync put: %v", put)
	}

	// the laptop (same user) sees everything merged
	l := newClient(t, base)
	l.auth = laptop.Token
	var doc struct {
		Rules  []store.Rule `json:"rules"`
		Policy struct {
			Lists       []string `json:"lists"`
			CustomLists []struct {
				ID, Name, URL string
			} `json:"customLists"`
			Services   []string          `json:"services"`
			Categories []string          `json:"categories"`
			SafeSearch policy.SafeSearch `json:"safeSearch"`
			BlockMode  string            `json:"blockMode"`
			Guard      struct {
				Enabled bool `json:"enabled"`
			} `json:"guard"`
			BypassBlocking bool `json:"bypassBlocking"`
		} `json:"policy"`
		Effective struct {
			Allow, Block []string
		} `json:"effective"`
		Locked struct {
			Lists        []string `json:"lists"`
			Services     []string `json:"services"`
			BlockDomains []string `json:"blockDomains"`
		} `json:"locked"`
		UserPolicy    policy.Policy `json:"userPolicy"`
		PolicyVersion string        `json:"policyVersion"`
	}
	if code := l.do("GET", "/api/v1/sync", nil, &doc, false); code != 200 {
		t.Fatalf("sync get: %d", code)
	}
	if len(doc.Rules) != 4 { // allow netblock, tombstone block netblock, block mine, (tombstone allow mine), gone tombstone
		t.Logf("rules: %+v", doc.Rules)
	}
	has := func(s []string, v string) bool {
		for _, x := range s {
			if x == v {
				return true
			}
		}
		return false
	}
	if !has(doc.Policy.Services, "tiktok") || !has(doc.Policy.Services, "youtube") || !has(doc.Locked.Services, "tiktok") || has(doc.Locked.Services, "youtube") {
		t.Fatalf("services: %v locked %v", doc.Policy.Services, doc.Locked.Services)
	}
	if !has(doc.Policy.Lists, "hagezi_pro") || has(doc.Locked.Lists, "hagezi_pro") || len(doc.Policy.CustomLists) != 1 || doc.Policy.CustomLists[0].URL != "https://example.com/list.txt" {
		t.Fatalf("lists: %v custom %+v", doc.Policy.Lists, doc.Policy.CustomLists)
	}
	if !doc.Policy.SafeSearch.Google || doc.Policy.BlockMode != "nxdomain" || !doc.Policy.Guard.Enabled || !doc.Policy.BypassBlocking {
		t.Fatalf("policy: %+v", doc.Policy)
	}
	if has(doc.Effective.Allow, "netblock.example") || !has(doc.Effective.Block, "netblock.example") || !has(doc.Effective.Block, "mine.example") || !has(doc.Locked.BlockDomains, "netblock.example") {
		t.Fatalf("effective: %+v locked %v", doc.Effective, doc.Locked.BlockDomains)
	}
	if !has(doc.UserPolicy.Services, "youtube") || doc.PolicyVersion == "" {
		t.Fatalf("userPolicy: %+v", doc.UserPolicy)
	}
	ver := doc.PolicyVersion
	l.do("GET", "/api/v1/sync", nil, &doc, false)
	if doc.PolicyVersion != ver {
		t.Fatal("policyVersion must be stable when nothing changed")
	}
	admin.do("POST", "/api/v1/rules?scope=default", map[string]string{"kind": "block", "domain": "another.example"}, nil, true)
	l.do("GET", "/api/v1/sync", nil, &doc, false)
	if doc.PolicyVersion == ver {
		t.Fatal("policyVersion must change with the network policy")
	}
	// the user's devices are enforced in DNS too: network block beats the user's allow
	if d := lastAPI.Engine.Decide(phone.Device.ID, "netblock.example"); !d.Blocked {
		t.Fatal("DNS: network block must beat user allow")
	}
	if d := lastAPI.Engine.Decide(phone.Device.ID, "www.youtube.com"); !d.Blocked {
		t.Fatal("DNS: user extra service")
	}
	if d := lastAPI.Engine.Decide("", "www.youtube.com"); d.Blocked {
		t.Fatal("user extras must not leak to the network")
	}

	// device tokens also pull the Guard blocklist
	resp := getRaw(t, base+"/api/v1/guard/blocklist.txt", "Bearer "+laptop.Token, "")
	if resp != 200 {
		t.Fatalf("blocklist with device token: %d", resp)
	}

	// disabling the user kills sessions and device tokens
	if code := admin.do("PUT", "/api/v1/users/"+strconv.FormatInt(uid, 10), map[string]any{"disabled": true}, nil, true); code != 200 {
		t.Fatalf("disable: %d", code)
	}
	if code := l.do("GET", "/api/v1/sync", nil, nil, false); code != 401 {
		t.Fatalf("disabled user's device token still works: %d", code)
	}
	if code := user.do("GET", "/api/v1/me", nil, nil, false); code != 401 {
		t.Fatalf("disabled user's session still works: %d", code)
	}
	// delete removes their devices
	if code := admin.do("DELETE", "/api/v1/users/"+strconv.FormatInt(uid, 10), nil, nil, true); code != 204 {
		t.Fatalf("delete user: %d", code)
	}
	var devs []map[string]any
	admin.do("GET", "/api/v1/devices", nil, &devs, false)
	if len(devs) != 0 {
		t.Fatalf("devices left: %v", devs)
	}
}

func getRaw(t *testing.T, url, auth, apiKey string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if apiKey != "" {
		req.Header.Set("X-Api-Key", apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	lastBody = string(body)
	return resp.StatusCode
}

var lastBody string

func TestUserRoles(t *testing.T) {
	admin, user, _, uid := adminAndUser(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/settings"}, {"PUT", "/api/v1/lists"}, {"GET", "/api/v1/guard"}, {"POST", "/api/v1/users"},
		{"GET", "/api/v1/rewrites"}, {"GET", "/api/v1/clients"}, {"GET", "/api/v1/users"},
	} {
		if code := user.do(c.method, c.path, map[string]any{}, nil, true); code != 403 {
			t.Errorf("%s %s as user: %d", c.method, c.path, code)
		}
	}
	// users see only their own devices
	adminDev := map[string]any{}
	admin.do("POST", "/api/v1/devices", map[string]any{"name": "TV", "ips": []string{"192.168.1.40"}}, &adminDev, true)
	var mine map[string]any
	user.do("POST", "/api/v1/devices", map[string]any{"name": "Tablet"}, &mine, true)
	var list []map[string]any
	user.do("GET", "/api/v1/devices", nil, &list, false)
	if len(list) != 1 || list[0]["name"] != "Tablet" {
		t.Fatalf("user devices: %v", list)
	}
	if code := user.do("PUT", "/api/v1/policy?scope=device:"+adminDev["id"].(string), policy.Policy{}, nil, true); code != 403 {
		t.Fatalf("user edited another device: %d", code)
	}
	if code := user.do("PUT", "/api/v1/devices/"+mine["id"].(string), map[string]any{"paused": true}, nil, true); code != 403 {
		t.Fatalf("user paused protection: %d", code)
	}
	// user extras via the dashboard (no schedules for user scope)
	if code := user.do("PUT", "/api/v1/policy?scope=user", policy.Policy{Categories: []string{"adult"}}, nil, true); code != 200 {
		t.Fatalf("user extras: %d", code)
	}
	if code := user.do("PUT", "/api/v1/policy?scope=user:"+strconv.FormatInt(uid+1, 10), policy.Policy{}, nil, true); code != 403 {
		t.Fatalf("user edited someone else's extras: %d", code)
	}
	// can't remove the last admin or yourself
	var me store.User
	admin.do("GET", "/api/v1/me", nil, &me, false)
	if code := admin.do("DELETE", "/api/v1/users/"+strconv.FormatInt(me.ID, 10), nil, nil, true); code != 400 {
		t.Fatalf("admin deleted self: %d", code)
	}
	var users []store.User
	admin.do("GET", "/api/v1/users", nil, &users, false)
	if len(users) != 2 || users[1].DeviceCount != 1 {
		t.Fatalf("users: %+v", users)
	}
	// password reset signs the user out
	admin.do("PUT", "/api/v1/users/"+strconv.FormatInt(uid, 10), map[string]any{"password": "a brand new password"}, nil, true)
	if code := user.do("GET", "/api/v1/me", nil, nil, false); code != 401 {
		t.Fatalf("session survived a password reset: %d", code)
	}
}

func TestGuardBouncerExport(t *testing.T) {
	admin, _, base, _ := adminAndUser(t)
	if code := getRaw(t, base+"/api/v1/guard/blocklist.txt", "", ""); code != 401 {
		t.Fatalf("no key: %d", code)
	}
	if code := getRaw(t, base+"/api/v1/guard/blocklist.txt", "", "zlb_wrong"); code != 401 {
		t.Fatalf("wrong key: %d", code)
	}
	var b struct {
		Key string `json:"key"`
	}
	admin.do("POST", "/api/v1/guard/bouncers", map[string]string{"name": "OPNsense"}, &b, true)
	if !strings.HasPrefix(b.Key, "zlb_") {
		t.Fatalf("key: %+v", b)
	}
	if code := admin.do("POST", "/api/v1/guard/bans", map[string]any{"ip": "198.51.100.23", "minutes": 60, "reason": "test"}, nil, true); code != 201 {
		t.Fatalf("manual ban: %d", code)
	}
	if code := admin.do("POST", "/api/v1/guard/bans", map[string]any{"ip": "127.0.0.1"}, nil, true); code != 400 {
		t.Fatalf("banning loopback must fail: %d", code)
	}
	if code := getRaw(t, base+"/api/v1/guard/blocklist.txt", "", b.Key); code != 200 || !strings.Contains(lastBody, "198.51.100.23\n") {
		t.Fatalf("export with key: %d %q", code, lastBody)
	}
	if code := getRaw(t, base+"/api/v1/guard/blocklist.txt?key="+b.Key+"&family=6", "", ""); code != 200 || strings.Contains(lastBody, "198.51.100.23") {
		t.Fatalf("?key= and family filter: %d %q", code, lastBody)
	}
	admin.do("POST", "/api/v1/guard/unban", map[string]string{"ip": "198.51.100.23"}, nil, true)
	getRaw(t, base+"/api/v1/guard/blocklist.txt", "Bearer "+b.Key, "")
	if strings.Contains(lastBody, "198.51.100.23") {
		t.Fatal("unbanned IP still exported")
	}
}

func TestRewritesAndClients(t *testing.T) {
	admin, _, _, _ := adminAndUser(t)
	var rw policy.Rewrite
	if code := admin.do("POST", "/api/v1/rewrites", map[string]string{"domain": "NAS.lan.", "type": "a", "value": "192.168.1.10"}, &rw, true); code != 201 || rw.Domain != "nas.lan" || rw.ID == "" {
		t.Fatalf("add rewrite: %d %+v", code, rw)
	}
	if code := admin.do("POST", "/api/v1/rewrites", map[string]string{"domain": "x.lan", "type": "A", "value": "nope"}, nil, true); code != 400 {
		t.Fatalf("bad rewrite: %d", code)
	}
	if d := lastAPI.Engine.Decide("", "nas.lan"); len(d.Local) != 1 {
		t.Fatalf("rewrite not live: %+v", d)
	}
	admin.do("DELETE", "/api/v1/rewrites/"+rw.ID, nil, nil, true)
	if d := lastAPI.Engine.Decide("", "nas.lan"); len(d.Local) != 0 {
		t.Fatal("rewrite not removed")
	}
	var dev map[string]any
	if code := admin.do("POST", "/api/v1/clients/name", map[string]string{"ip": "192.168.1.77", "name": "Printer"}, &dev, true); code != 201 {
		t.Fatalf("name client: %d", code)
	}
	if lastAPI.Engine.DeviceForIP("192.168.1.77") != dev["id"] {
		t.Fatal("client not mapped to the new device")
	}
}
