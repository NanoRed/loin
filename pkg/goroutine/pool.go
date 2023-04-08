package goroutine

import (
	"time"

	"github.com/NanoRed/loin/pkg/logger"
)

type Pool struct {
	Workers chan *Worker
}

func NewPool(workerNum int) (pool *Pool) {
	pool = &Pool{
		Workers: make(chan *Worker, workerNum),
	}
	for i := 0; i < workerNum; i++ {
		worker := NewWorker()
		worker.Start()
		worker.Pool = pool
		pool.Workers <- worker
	}
	return
}

func (p *Pool) Add(task Task) {
	select {
	case worker := <-p.Workers:
		worker.Tasks <- task
	default:
		logger.Error("failed to add task, you may need to consider expanding the pool.")
	}
}

func (p *Pool) AddTimeout(task Task, timeout time.Duration) {
	select {
	case worker := <-p.Workers:
		worker.Tasks <- task
	case <-time.After(timeout):
		logger.Error("adding task timeout, you may need to consider expanding the pool.")
	}
}

var CommonPool *Pool = NewPool(10)
