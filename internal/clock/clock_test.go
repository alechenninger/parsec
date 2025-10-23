package clock

import (
	"testing"
	"time"
)

func TestSystemClock_Now(t *testing.T) {
	clock := NewSystemClock()

	before := time.Now()
	now := clock.Now()
	after := time.Now()

	if now.Before(before) || now.After(after) {
		t.Errorf("SystemClock.Now() returned time outside expected range: %v not between %v and %v", now, before, after)
	}
}

func TestFixtureClock_Now(t *testing.T) {
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := NewFixtureClock(startTime)

	now := clock.Now()
	if !now.Equal(startTime) {
		t.Errorf("expected time %v, got %v", startTime, now)
	}
}

func TestFixtureClock_DefaultsToNow(t *testing.T) {
	before := time.Now()
	clock := NewFixtureClock(time.Time{}) // zero time
	after := time.Now()

	now := clock.Now()
	if now.Before(before) || now.After(after) {
		t.Errorf("FixtureClock with zero time should default to time.Now(), got %v", now)
	}
}

func TestFixtureClock_Set(t *testing.T) {
	clock := NewFixtureClock(time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC))

	newTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	clock.Set(newTime)

	if !clock.Now().Equal(newTime) {
		t.Errorf("expected time %v, got %v", newTime, clock.Now())
	}
}

func TestFixtureClock_Advance(t *testing.T) {
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := NewFixtureClock(startTime)

	t.Run("advance by hours", func(t *testing.T) {
		clock.Advance(2 * time.Hour)
		expected := startTime.Add(2 * time.Hour)
		if !clock.Now().Equal(expected) {
			t.Errorf("expected time %v, got %v", expected, clock.Now())
		}
	})

	t.Run("advance by days", func(t *testing.T) {
		clock.Set(startTime) // reset
		clock.Advance(24 * time.Hour)
		expected := startTime.Add(24 * time.Hour)
		if !clock.Now().Equal(expected) {
			t.Errorf("expected time %v, got %v", expected, clock.Now())
		}
	})

	t.Run("advance by minutes", func(t *testing.T) {
		clock.Set(startTime) // reset
		clock.Advance(30 * time.Minute)
		expected := startTime.Add(30 * time.Minute)
		if !clock.Now().Equal(expected) {
			t.Errorf("expected time %v, got %v", expected, clock.Now())
		}
	})

	t.Run("multiple advances accumulate", func(t *testing.T) {
		clock.Set(startTime) // reset
		clock.Advance(1 * time.Hour)
		clock.Advance(30 * time.Minute)
		clock.Advance(15 * time.Second)
		expected := startTime.Add(1*time.Hour + 30*time.Minute + 15*time.Second)
		if !clock.Now().Equal(expected) {
			t.Errorf("expected time %v, got %v", expected, clock.Now())
		}
	})
}

func TestFixtureClock_Rewind(t *testing.T) {
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := NewFixtureClock(startTime)

	t.Run("rewind by hours", func(t *testing.T) {
		clock.Rewind(2 * time.Hour)
		expected := startTime.Add(-2 * time.Hour)
		if !clock.Now().Equal(expected) {
			t.Errorf("expected time %v, got %v", expected, clock.Now())
		}
	})

	t.Run("rewind and advance", func(t *testing.T) {
		clock.Set(startTime) // reset
		clock.Advance(5 * time.Hour)
		clock.Rewind(2 * time.Hour)
		expected := startTime.Add(3 * time.Hour)
		if !clock.Now().Equal(expected) {
			t.Errorf("expected time %v, got %v", expected, clock.Now())
		}
	})
}

func TestFixtureClock_TimeIsFrozen(t *testing.T) {
	startTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := NewFixtureClock(startTime)

	// Multiple calls to Now() should return the same time
	now1 := clock.Now()
	time.Sleep(10 * time.Millisecond) // Wait a bit
	now2 := clock.Now()
	time.Sleep(10 * time.Millisecond) // Wait a bit more
	now3 := clock.Now()

	if !now1.Equal(now2) || !now2.Equal(now3) {
		t.Errorf("FixtureClock time should be frozen: got %v, %v, %v", now1, now2, now3)
	}

	if !now1.Equal(startTime) {
		t.Errorf("expected time %v, got %v", startTime, now1)
	}
}
