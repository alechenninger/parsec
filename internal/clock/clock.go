package clock

import "time"

// Clock abstracts time operations for testability
// This allows tests to control time without relying on the system clock
type Clock interface {
	// Now returns the current time
	Now() time.Time
}

// SystemClock uses the real system clock
type SystemClock struct{}

// NewSystemClock creates a clock that uses the real system time
func NewSystemClock() *SystemClock {
	return &SystemClock{}
}

// Now returns the current system time
func (c *SystemClock) Now() time.Time {
	return time.Now()
}

// FixtureClock is a controllable clock for testing
// It allows tests to set specific times and advance time programmatically
type FixtureClock struct {
	currentTime time.Time
}

// NewFixtureClock creates a fixture clock starting at the given time
// If zero time is provided, uses time.Now()
func NewFixtureClock(startTime time.Time) *FixtureClock {
	if startTime.IsZero() {
		startTime = time.Now()
	}
	return &FixtureClock{
		currentTime: startTime,
	}
}

// Now returns the current fixture time
func (c *FixtureClock) Now() time.Time {
	return c.currentTime
}

// Set sets the fixture clock to a specific time
func (c *FixtureClock) Set(t time.Time) {
	c.currentTime = t
}

// Advance moves the fixture clock forward by the given duration
func (c *FixtureClock) Advance(d time.Duration) {
	c.currentTime = c.currentTime.Add(d)
}

// Rewind moves the fixture clock backward by the given duration
func (c *FixtureClock) Rewind(d time.Duration) {
	c.currentTime = c.currentTime.Add(-d)
}
