//go:build linux || darwin

package agent

// Shared, platform-neutral cancellation scaffold for the Unix packet device
// backends (Linux TUN and macOS utun).
//
// Both backends open a non-blocking character device and must interrupt a
// blocked read when either the caller's context is done or the device is closed.
// A non-blocking descriptor cannot express that with a read deadline, so each
// device carries a wake descriptor (eventfd on Linux, pipe on macOS) that Close
// and context cancellation signal; a poll over {device, wake} then returns
// immediately. No goroutine is leaked, Close never closes the device descriptor
// while another goroutine is inside poll/read, and a cancellation never consumes
// a packet.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// descriptorWake is one wake channel: a single eventfd on Linux or a pipe on
// macOS. readFd is always valid; writeFd equals readFd for eventfd.
type descriptorWake struct {
	readFd  int
	writeFd int
}

// signal wakes a blocked poll. It uses a non-blocking write: if the counter or
// pipe is already full the waiter is already runnable, so the error is dropped.
func (w descriptorWake) signal() {
	if w.writeFd < 0 {
		return
	}
	var token [8]byte
	token[0] = 1
	_, _ = unix.Write(w.writeFd, token[:])
}

// drain resets the wake channel so the next poll does not return spuriously.
func (w descriptorWake) drain() {
	if w.readFd < 0 {
		return
	}
	var token [8]byte
	for {
		if _, err := unix.Read(w.readFd, token[:]); err != nil {
			return
		}
	}
}

// close releases both descriptors exactly once.
func (w descriptorWake) close() {
	if w.readFd >= 0 {
		_ = unix.Close(w.readFd)
	}
	if w.writeFd >= 0 && w.writeFd != w.readFd {
		_ = unix.Close(w.writeFd)
	}
}

// pollTimeoutMillis converts the context deadline into a poll timeout. It
// returns -1 (block until an event) when the context has no deadline.
func pollTimeoutMillis(ctx context.Context) int {
	if ctx == nil {
		return -1
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return -1
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	millis := int(remaining / time.Millisecond)
	if millis <= 0 {
		return 1
	}
	return millis
}

// pollDevice waits until fd is ready for events, the context is done, the
// device is closed (through the wake channel) or an error is reported by poll.
// A context without a deadline blocks until one of the two descriptors becomes
// ready. Interrupted polls are retried; a descriptor that is no longer valid is
// reported as ErrDeviceClosed so the caller does not touch a reused fd.
func pollDevice(ctx context.Context, fd int, events int16, wake descriptorWake, name string) error {
	// The join is mandatory: the caller releases its device lock when this
	// returns, and Close may then close (and the process may reuse) the wake
	// descriptor. Returning while the cancellation callback could still write to
	// it would turn cancellation into a write to an unrelated descriptor.
	defer afterFuncJoined(ctx, wake.signal)()

	descriptors := []unix.PollFd{
		{Fd: int32(fd), Events: events},
		{Fd: int32(wake.readFd), Events: unix.POLLIN},
	}
	for {
		if err := packetDeviceContextErr(ctx); err != nil {
			return fmt.Errorf("agent: %s: %w", name, err)
		}
		timeout := pollTimeoutMillis(ctx)
		ready, err := unix.Poll(descriptors, timeout)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("agent: poll %s: %w", name, err)
		}
		if descriptors[1].Revents != 0 {
			// Close and context cancellation both arrive through the wake
			// channel. Draining and returning lets the caller re-check its own
			// closed flag and context before touching the descriptor again; a
			// cancel that consumed no packet is retried, never lost.
			wake.drain()
			return nil
		}
		if descriptors[0].Revents&unix.POLLNVAL != 0 {
			return fmt.Errorf("agent: %s: %w", name, ErrDeviceClosed)
		}
		if ready > 0 && descriptors[0].Revents&(events|unix.POLLERR|unix.POLLHUP) != 0 {
			return nil
		}
		// A deadline slice may expire without either descriptor being ready, and
		// poll may also report spurious readiness. Both simply loop.
	}
}
