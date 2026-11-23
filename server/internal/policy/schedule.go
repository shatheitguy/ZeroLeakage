package policy

import (
	"fmt"
	"strings"
	"time"
)

// Schedule actions.
const (
	ActionBlockAll      = "block_all"      // everything except the schedule's allowlist
	ActionBlockSelected = "block_selected" // only the chosen services / categories
)

// Schedule is a recurring time window (server time zone) during which extra blocking applies,
// e.g. "Bedtime: Sun-Thu 21:00-07:00, block everything except school.example.com".
type Schedule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Enabled    bool     `json:"enabled"`
	Days       []int    `json:"days"`  // 0=Sunday … 6=Saturday: the day the window starts
	Start      string   `json:"start"` // "HH:MM"
	End        string   `json:"end"`   // "HH:MM"; End <= Start means the window runs past midnight
	Action     string   `json:"action"`
	Services   []string `json:"services,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Allow      []string `json:"allow,omitempty"` // block_all exceptions (domain + subdomains)
}

func parseHM(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d:%d", &h, &m); err != nil || h < 0 || h > 24 || m < 0 || m > 59 || (h == 24 && m != 0) {
		return 0, fmt.Errorf("time must be HH:MM, got %q", s)
	}
	return h*60 + m, nil
}

// Validate checks a schedule and normalises it.
func (s *Schedule) Validate() error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		s.Name = "Schedule"
	}
	if len(s.Name) > 60 {
		s.Name = s.Name[:60]
	}
	if _, err := parseHM(s.Start); err != nil {
		return err
	}
	if _, err := parseHM(s.End); err != nil {
		return err
	}
	seen := map[int]bool{}
	var days []int
	for _, d := range s.Days {
		if d < 0 || d > 6 {
			return fmt.Errorf("days are 0 (Sunday) to 6 (Saturday)")
		}
		if !seen[d] {
			seen[d] = true
			days = append(days, d)
		}
	}
	if len(days) == 0 {
		return fmt.Errorf("pick at least one day")
	}
	s.Days = days
	switch s.Action {
	case ActionBlockAll, ActionBlockSelected:
	default:
		return fmt.Errorf("action must be block_all or block_selected")
	}
	return nil
}

// compiledSchedule is a schedule ready for the hot path.
type compiledSchedule struct {
	src      Schedule
	days     [7]bool
	start    int // minutes after midnight
	end      int
	services uint64
	lists    []string // resolved list ids for the schedule's categories
	allow    map[string]bool
}

func compileSchedule(s Schedule) compiledSchedule {
	c := compiledSchedule{src: s, services: ServiceMask(s.Services), allow: map[string]bool{}}
	c.start, _ = parseHM(s.Start)
	c.end, _ = parseHM(s.End)
	for _, d := range s.Days {
		if d >= 0 && d <= 6 {
			c.days[d] = true
		}
	}
	for _, a := range s.Allow {
		c.allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return c
}

// ActiveAt reports whether the schedule's window covers t (in t's location).
func (s Schedule) ActiveAt(t time.Time) bool {
	c := compileSchedule(s)
	return s.Enabled && c.active(t)
}

func (c *compiledSchedule) active(t time.Time) bool {
	now := t.Hour()*60 + t.Minute()
	today := int(t.Weekday())
	yesterday := (today + 6) % 7
	switch {
	case c.start == c.end: // all day
		return c.days[today]
	case c.start < c.end:
		return c.days[today] && now >= c.start && now < c.end
	default: // crosses midnight: started today, or started yesterday and not over yet
		return (c.days[today] && now >= c.start) || (c.days[yesterday] && now < c.end)
	}
}
