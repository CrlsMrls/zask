package ebpf

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/rs/zerolog"
)

// RingBufReader continuously polls the eBPF ring buffer and pushes
// decoded events to an output channel. It runs in a dedicated goroutine
// and stops when the context is canceled.
type RingBufReader struct {
	reader *ringbuf.Reader
	log    zerolog.Logger
}

// NewRingBufReader creates a ring buffer reader for the given eBPF events map.
func NewRingBufReader(loader *Loader, log zerolog.Logger) (*RingBufReader, error) {
	rd, err := ringbuf.NewReader(loader.Objects().Events)
	if err != nil {
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}
	return &RingBufReader{
		reader: rd,
		log:    log.With().Str("component", "ringbuf-reader").Logger(),
	}, nil
}

// Run starts the polling loop, decoding events and sending them to the
// output channel. Blocks until the context is canceled or an
// unrecoverable error occurs. Close must be called to release resources.
func (r *RingBufReader) Run(ctx context.Context, out chan<- ZaskEvent) error {
	r.log.Info().Msg("ring buffer reader started")

	for {
		select {
		case <-ctx.Done():
			r.log.Info().Msg("ring buffer reader stopping (context canceled)")
			return nil
		default:
		}

		record, err := r.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				r.log.Info().Msg("ring buffer closed")
				return nil
			}
			r.log.Error().Err(err).Msg("reading ring buffer")
			continue
		}

		ev, err := DecodeEvent(record.RawSample)
		if err != nil {
			r.log.Error().Err(err).Msg("decoding ring buffer event")
			continue
		}

		r.log.Debug().
			Uint32("pid", ev.Pid).
			Uint32("ppid", ev.Ppid).
			Uint32("uid", ev.Uid).
			Uint64("inode", ev.InodeNumber).
			Str("argv", ev.GetArgv()).
			Msg("event received")

		select {
		case out <- ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// Close stops the ring buffer reader and releases resources.
func (r *RingBufReader) Close() error {
	return r.reader.Close()
}
