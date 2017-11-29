package authfile

// WorkPool implements a bounded worker pool.
type WorkPool struct {
	workers int
	pool    chan chan interface{}
}

type quitMsg struct{}

type jobMsg struct {
	job func()
}

// NewWorkPool creates a new worker pool with maxworkers workers.
func NewWorkPool(maxworkers int) *WorkPool {
	wp := &WorkPool{
		workers: maxworkers,
		pool:    make(chan chan interface{}, maxworkers),
	}
	for i := 0; i < maxworkers; i++ {
		go wp.worker(i)
	}
	return wp
}

// Dispatch a job to the workPool. It will block when no workers are
// available. It returns true after successful dispatch, or false if
// the workpool is unavailable.
func (wp *WorkPool) Dispatch(job func()) (res bool) {
	for worker := range wp.pool {
		worker <- jobMsg{
			job: job,
		}
		return true
	}
	return false
}

// Shutdown the workpool.
func (wp *WorkPool) Shutdown() {
	for i := 0; i < wp.workers; i++ {
		worker := <-wp.pool
		worker <- quitMsg{}
	}
	close(wp.pool)
}

func (wp *WorkPool) worker(id int) {
	jobs := make(chan interface{}, 1)
	wp.pool <- jobs
	for m := range jobs {
		switch e := m.(type) {
		case quitMsg:
			close(jobs)
			return
		case jobMsg:
			wp.pool <- jobs
			runjob(e.job)
		}
	}
}

func runjob(job func()) {
	defer recover()
	job()
}
