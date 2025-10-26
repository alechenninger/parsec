package clock

import (
	"context"
	"time"
)

// Ticker is an interface for a ticker that periodically calls a function
type Ticker interface {
	// Start begins calling the function periodically
	// The function is called with a context that is cancelled when Stop is called
	Start(fn func(context.Context)) error
	// Stop stops the ticker and cancels any in-flight function calls
	Stop()
}

// Clock abstracts time operations for testability
// This allows tests to control time without relying on the system clock
type Clock interface {
	// Now returns the current time
	Now() time.Time
	// Ticker creates a new ticker that ticks at the given interval
	Ticker(d time.Duration) Ticker
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

// Ticker creates a real time.Ticker wrapped in our interface
func (c *SystemClock) Ticker(d time.Duration) Ticker {
	return &systemTicker{ticker: time.NewTicker(d)}
}

// systemTicker wraps time.Ticker to implement our Ticker interface
type systemTicker struct {
	ticker *time.Ticker
	cancel context.CancelFunc
	done   chan struct{}
}

func (t *systemTicker) Start(fn func(context.Context)) error {
	ctx, cancel := context.WithCancel(context.Background())
	t.cancel = cancel
	t.done = make(chan struct{})

	go func() {
		defer close(t.done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.ticker.C:
				fn(ctx)
			}
		}
	}()

	return nil
}

func (t *systemTicker) Stop() {
	if t.cancel != nil {
		t.cancel()
		<-t.done // Wait for goroutine to finish
	}
	t.ticker.Stop()
}

// FixtureClock is a controllable clock for testing
// It allows tests to set specific times and advance time programmatically
type FixtureClock struct {
	currentTime time.Time
	tickers     []*fixtureTicker
}

// NewFixtureClock creates a fixture clock starting at the given time
// If zero time is provided, uses time.Now()
func NewFixtureClock(startTime time.Time) *FixtureClock {
	if startTime.IsZero() {
		startTime = time.Now()
	}
	return &FixtureClock{
		currentTime: startTime,
		tickers:     make([]*fixtureTicker, 0),
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
// and triggers any tickers that should fire
func (c *FixtureClock) Advance(d time.Duration) {
	c.currentTime = c.currentTime.Add(d)
	// Trigger tickers
	for _, ticker := range c.tickers {
		ticker.checkTick(c.currentTime)
	}
}

// Rewind moves the fixture clock backward by the given duration
func (c *FixtureClock) Rewind(d time.Duration) {
	c.currentTime = c.currentTime.Add(-d)
}

// Ticker creates a fixture ticker for testing
func (c *FixtureClock) Ticker(d time.Duration) Ticker {
	ticker := &fixtureTicker{
		interval: d,
		nextTick: c.currentTime.Add(d),
		stopped:  false,
	}
	c.tickers = append(c.tickers, ticker)
	return ticker
}

// fixtureTicker is a controllable ticker for testing
type fixtureTicker struct {
	interval time.Duration
	nextTick time.Time
	fn       func(context.Context)
	stopped  bool
}

func (t *fixtureTicker) Start(fn func(context.Context)) error {
	t.fn = fn
	return nil
}

func (t *fixtureTicker) Stop() {
	t.stopped = true
}

// checkTick calls the function if the current time has passed the next tick time
func (t *fixtureTicker) checkTick(now time.Time) {
	if t.stopped || t.fn == nil {
		return
	}

	for !now.Before(t.nextTick) {
		// Call the function with a background context
		t.fn(context.Background())
		t.nextTick = t.nextTick.Add(t.interval)
	}
}
