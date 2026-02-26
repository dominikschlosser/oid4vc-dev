package output

import (
	"testing"
	"time"
)

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"future 13 days", now.Add(13 * 24 * time.Hour), "in 13 days"},
		{"past 1 day", now.Add(-24 * time.Hour), "1 day ago"},
		{"past 3 days", now.Add(-3 * 24 * time.Hour), "3 days ago"},
		{"future 2 hours", now.Add(2 * time.Hour), "in 2 hours"},
		{"future 1 hour", now.Add(1 * time.Hour), "in 1 hour"},
		{"future 90 days", now.Add(90 * 24 * time.Hour), "in 3 months"},
		{"past 60 days", now.Add(-60 * 24 * time.Hour), "2 months ago"},
		{"future 30 minutes", now.Add(30 * time.Minute), "in 30 minutes"},
		{"past 30 seconds", now.Add(-30 * time.Second), "1 minute ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativeTime(tt.t)
			if got != tt.want {
				t.Errorf("relativeTime() = %q, want %q", got, tt.want)
			}
		})
	}
}
