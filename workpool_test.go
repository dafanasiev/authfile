package authfile

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func Test_Pool(t *testing.T) {
	var counter int32
	workers := 5
	wp := NewWorkPool(workers)
	time.Sleep(time.Millisecond)

	for i := 0; i < workers*2; i++ {
		if ok := wp.Dispatch(func() { atomic.AddInt32(&counter, 1) }); !ok {
			t.Error("WorkPool unavailable")
		}
	}
	wp.Shutdown()
	time.Sleep(time.Millisecond)
	if ok := wp.Dispatch(func() { fmt.Println("JOB") }); ok {
		t.Error("Dispatch must return false")
	}
	if counter != int32(workers*2) {
		t.Error("Not all work dispatched")
	}
}
