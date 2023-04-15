package goroutine

type Worker struct {
	Pool  *Pool
	Tasks chan Task
}

func NewWorker(cap int) (worker *Worker) {
	worker = &Worker{
		Tasks: make(chan Task, cap),
	}
	return
}

func (w *Worker) Start() {
	go func() {
		for f := range w.Tasks {
			f()
		}
	}()
}
