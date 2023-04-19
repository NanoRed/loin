package internal

import (
	"bytes"
	"encoding/gob"
	"sync"
)

const (
	HubMaxLen int = 8
)

type Junction struct {
	Hub   [HubMaxLen]*Link
	Free  chan int
	Guide map[string]int
	Lock  sync.RWMutex
}

func NewJunction() (junction *Junction) {
	junction = &Junction{
		Guide: make(map[string]int),
		Free:  make(chan int, HubMaxLen),
	}
	for i := 0; i < HubMaxLen; i++ {
		junction.Free <- i
	}
	return
}

func (j *Junction) Register(link *Link) (id int, ok bool) {
	j.Lock.Lock()
	defer j.Lock.Unlock()
	if id, ok = <-j.Free; ok {
		j.Hub[id] = link
		j.Guide[link.From.GetIP().String()] = id
	}
	return
}

func (j *Junction) Unregister(id int) {
	j.Lock.Lock()
	defer j.Lock.Unlock()
	link := j.Hub[id]
	j.Hub[id] = nil
	j.Free <- id
	delete(j.Guide, link.From.GetIP().String())
}

func (j *Junction) Range(fn func(key string, id int, link *Link)) {
	j.Lock.RLock()
	defer j.Lock.RUnlock()
	for key, id := range j.Guide {
		fn(key, id, j.Hub[id])
	}
}

func (j *Junction) GetID(key string) (id int, ok bool) {
	j.Lock.RLock()
	defer j.Lock.RUnlock()
	id, ok = j.Guide[key]
	return
}

func (j *Junction) GetLink(id int) (link *Link) {
	j.Lock.RLock()
	defer j.Lock.RUnlock()
	link = j.Hub[id]
	return
}

func (j *Junction) EncodeGuide() []byte {
	j.Lock.RLock()
	defer j.Lock.RUnlock()
	var buffer bytes.Buffer
	gob.NewEncoder(&buffer).Encode(j.Guide)
	return buffer.Bytes()
}

func (j *Junction) DecodeGuide(b []byte) {
	j.Lock.Lock()
	defer j.Lock.Unlock()
	gob.NewDecoder(bytes.NewBuffer(b)).Decode(&j.Guide)
}

func (j *Junction) Close() {
	j.Lock.RLock()
	defer j.Lock.RUnlock()
	for _, link := range j.Hub {
		if link != nil {
			link.Close()
		}
	}
}
