package goroutine

import (
	"math/rand"

	"github.com/NanoRed/loin/pkg/logger"
)

type Pool struct {
	Workers []*Worker
}

func NewPool(workerNum int, workerCap int) (pool *Pool) {
	pool = &Pool{
		Workers: make([]*Worker, workerNum),
	}
	for i := 0; i < workerNum; i++ {
		worker := NewWorker(workerCap)
		worker.Start()
		worker.Pool = pool
		pool.Workers[i] = worker
	}
	return
}

func (p *Pool) Add(task Task) {
	select {
	case p.Workers[rand.Intn(len(p.Workers))].Tasks <- task:
	default:
		go task()
		logger.Warn("failed to add task, you may need to consider expanding the pool.")
	}
}
