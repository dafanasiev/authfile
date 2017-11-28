package authfile

import "time"

type bufferFlush struct{}

// MsgBuffer is a timed message buffer. Close the returned channel to stop it.
func MsgBuffer(out chan interface{}, wait time.Duration) chan interface{} {
	in := make(chan interface{}, 10)
	go func() {
		var flushwait = false
		buffer := make([]interface{}, 0, 10)
		for m := range in {
			switch m.(type) {
			case bufferFlush:
				flushwait = false
				if len(buffer) > 0 {
					oldbuffer := buffer
					buffer = make([]interface{}, 0, 10)
					go func() { // Flush buffer in goroutine to prevent locking the channel through a loop.
						for _, e := range oldbuffer {
							out <- e
						}
					}()
				}
			default:
				if !flushwait {
					flushwait = true
					time.AfterFunc(wait, func() {
						defer recover() // Can panic if channel has been closed in the meantime.
						in <- bufferFlush{}
					})
				}
				buffer = append(buffer, m)
			}
		}
	}()
	return in
}
