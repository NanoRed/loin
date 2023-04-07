package goroutine

type Worker struct {
	Pool  *Pool
	Tasks chan Task
}

func NewWorker() (worker *Worker) {
	worker = &Worker{
		Tasks: make(chan Task),
	}
	return
}

func (w *Worker) Start() {
	go func() {
		for f := range w.Tasks {
			f()
			w.Pool.Workers <- w
		}
	}()
}
