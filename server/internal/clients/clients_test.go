package clients

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/shatheitguy/ZeroLeakage/server/internal/netinfo"
	"github.com/shatheitguy/ZeroLeakage/server/internal/store"
)

func TestARPAndVendor(t *testing.T) {
	arp := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         B8:27:EB:12:34:56     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.20     0x1         0x2         da:a1:19:00:00:01     *        eth0
`
	m := ParseARP(strings.NewReader(arp))
	if len(m) != 2 || m["192.168.1.1"] != "b8:27:eb:12:34:56" {
		t.Fatalf("arp: %v", m)
	}
	if v := Vendor(m["192.168.1.1"]); v != "Raspberry Pi" {
		t.Fatalf("vendor = %q", v)
	}
	if !Randomized(m["192.168.1.20"]) || !strings.Contains(Vendor(m["192.168.1.20"]), "randomized") {
		t.Fatal("locally administered MAC not detected")
	}
	if Vendor("zz") != "" {
		t.Fatal("garbage MAC")
	}
}

func TestTrackerFlush(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	tr := NewTracker(st, slog.New(slog.NewTextHandler(io.Discard, nil)), func() string { return "" })
	tr.ReadARP = func() map[string]string { return map[string]string{"192.168.1.30": "b8:27:eb:00:00:01"} }
	now := time.Now().Unix()
	for i := 0; i < 5; i++ {
		tr.Observe("192.168.1.30", "udp", now)
	}
	tr.Flush(now)
	tr.Observe("192.168.1.30", "udp", now+1)
	tr.Flush(now + 1)
	tr.Enrich(t.Context(), now+2)
	cs, _ := st.Clients(10)
	if len(cs) != 1 || cs[0].Queries != 6 || cs[0].Vendor != "Raspberry Pi" || cs[0].MAC == "" {
		t.Fatalf("clients: %+v", cs)
	}
}

func TestRoutes(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\nrteth0\t00000000\t0101A8C0\t0003\neth0\t0001A8C0\t00000000\t0001\n"
	gw := netinfo.ParseRoutes(strings.NewReader(route))
	if len(gw) != 1 || gw[0].String() != "192.168.1.1" {
		t.Fatalf("gateways: %v", gw)
	}
}
