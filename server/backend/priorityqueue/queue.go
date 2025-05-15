package priorityqueue

import (
	"container/heap"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
)

// Priority levels
const (
	PriorityLow    = 0
	PriorityMedium = 1
	PriorityHigh   = 2
)

// LDAPRequestItem represents an item in the LDAP request priority queue
type LDAPRequestItem struct {
	Request    *bktype.LDAPRequest
	Priority   int
	InsertTime time.Time
	Index      int // Used by heap.Interface
}

// LDAPAuthRequestItem represents an item in the LDAP auth request priority queue
type LDAPAuthRequestItem struct {
	Request    *bktype.LDAPAuthRequest
	Priority   int
	InsertTime time.Time
	Index      int // Used by heap.Interface
}

// LuaRequestItem represents an item in the Lua request priority queue
type LuaRequestItem struct {
	Request    *bktype.LuaRequest
	Priority   int
	InsertTime time.Time
	Index      int // Used by heap.Interface
}

// LDAPRequestPriorityQueue implements heap.Interface and holds LDAPRequestItems
type LDAPRequestPriorityQueue []*LDAPRequestItem

// LDAPAuthRequestPriorityQueue implements heap.Interface and holds LDAPAuthRequestItems
type LDAPAuthRequestPriorityQueue []*LDAPAuthRequestItem

// LuaRequestPriorityQueue implements heap.Interface and holds LuaRequestItems
type LuaRequestPriorityQueue []*LuaRequestItem

// Implement heap.Interface for LDAPRequestPriorityQueue
func (pq LDAPRequestPriorityQueue) Len() int { return len(pq) }

func (pq LDAPRequestPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	// If priorities are equal, older requests come first
	return pq[i].InsertTime.Before(pq[j].InsertTime)
}

func (pq LDAPRequestPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

func (pq *LDAPRequestPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*LDAPRequestItem)
	item.Index = n
	*pq = append(*pq, item)
}

func (pq *LDAPRequestPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// Implement heap.Interface for LDAPAuthRequestPriorityQueue
func (pq LDAPAuthRequestPriorityQueue) Len() int { return len(pq) }

func (pq LDAPAuthRequestPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	// If priorities are equal, older requests come first
	return pq[i].InsertTime.Before(pq[j].InsertTime)
}

func (pq LDAPAuthRequestPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

func (pq *LDAPAuthRequestPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*LDAPAuthRequestItem)
	item.Index = n
	*pq = append(*pq, item)
}

func (pq *LDAPAuthRequestPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// Implement heap.Interface for LuaRequestPriorityQueue
func (pq LuaRequestPriorityQueue) Len() int { return len(pq) }

func (pq LuaRequestPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	// If priorities are equal, older requests come first
	return pq[i].InsertTime.Before(pq[j].InsertTime)
}

func (pq LuaRequestPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].Index = i
	pq[j].Index = j
}

func (pq *LuaRequestPriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := x.(*LuaRequestItem)
	item.Index = n
	*pq = append(*pq, item)
}

func (pq *LuaRequestPriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]
	return item
}

// LDAPRequestQueue manages a priority queue for LDAP requests
type LDAPRequestQueue struct {
	queue     LDAPRequestPriorityQueue
	mutex     sync.Mutex
	notEmpty  *sync.Cond
	poolNames map[string]bool
}

// LDAPAuthRequestQueue manages a priority queue for LDAP auth requests
type LDAPAuthRequestQueue struct {
	queue     LDAPAuthRequestPriorityQueue
	mutex     sync.Mutex
	notEmpty  *sync.Cond
	poolNames map[string]bool
}

// LuaRequestQueue manages a priority queue for Lua requests
type LuaRequestQueue struct {
	queue        LuaRequestPriorityQueue
	mutex        sync.Mutex
	notEmpty     *sync.Cond
	backendNames map[string]bool
}

// NewLDAPRequestQueue creates a new LDAPRequestQueue
func NewLDAPRequestQueue() *LDAPRequestQueue {
	q := &LDAPRequestQueue{
		queue:     make(LDAPRequestPriorityQueue, 0),
		poolNames: make(map[string]bool),
	}
	q.notEmpty = sync.NewCond(&q.mutex)
	heap.Init(&q.queue)
	return q
}

// NewLDAPAuthRequestQueue creates a new LDAPAuthRequestQueue
func NewLDAPAuthRequestQueue() *LDAPAuthRequestQueue {
	q := &LDAPAuthRequestQueue{
		queue:     make(LDAPAuthRequestPriorityQueue, 0),
		poolNames: make(map[string]bool),
	}
	q.notEmpty = sync.NewCond(&q.mutex)
	heap.Init(&q.queue)
	return q
}

// NewLuaRequestQueue creates a new LuaRequestQueue
func NewLuaRequestQueue() *LuaRequestQueue {
	q := &LuaRequestQueue{
		queue:        make(LuaRequestPriorityQueue, 0),
		backendNames: make(map[string]bool),
	}
	q.notEmpty = sync.NewCond(&q.mutex)
	heap.Init(&q.queue)
	return q
}

// AddPoolName adds a pool name to the LDAPRequestQueue
func (q *LDAPRequestQueue) AddPoolName(poolName string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.poolNames[poolName] = true
}

// GetPoolNames returns the pool names in the LDAPRequestQueue
func (q *LDAPRequestQueue) GetPoolNames() []string {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	var names []string
	for name := range q.poolNames {
		names = append(names, name)
	}
	return names
}

// AddPoolName adds a pool name to the LDAPAuthRequestQueue
func (q *LDAPAuthRequestQueue) AddPoolName(poolName string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.poolNames[poolName] = true
}

// GetPoolNames returns the pool names in the LDAPAuthRequestQueue
func (q *LDAPAuthRequestQueue) GetPoolNames() []string {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	var names []string
	for name := range q.poolNames {
		names = append(names, name)
	}
	return names
}

// AddBackendName adds a backend name to the LuaRequestQueue
func (q *LuaRequestQueue) AddBackendName(backendName string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	q.backendNames[backendName] = true
}

// GetBackendNames returns the backend names in the LuaRequestQueue
func (q *LuaRequestQueue) GetBackendNames() []string {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	var names []string
	for name := range q.backendNames {
		names = append(names, name)
	}
	return names
}

// Push adds a request to the LDAPRequestQueue with the given priority
func (q *LDAPRequestQueue) Push(request *bktype.LDAPRequest, priority int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	item := &LDAPRequestItem{
		Request:    request,
		Priority:   priority,
		InsertTime: time.Now(),
	}
	heap.Push(&q.queue, item)
	q.notEmpty.Signal()
}

// Pop removes and returns the highest priority request from the LDAPRequestQueue
// It blocks if the queue is empty
func (q *LDAPRequestQueue) Pop() *bktype.LDAPRequest {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	for q.queue.Len() == 0 {
		q.notEmpty.Wait()
	}

	item := heap.Pop(&q.queue).(*LDAPRequestItem)
	return item.Request
}

// Push adds a request to the LDAPAuthRequestQueue with the given priority
func (q *LDAPAuthRequestQueue) Push(request *bktype.LDAPAuthRequest, priority int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	item := &LDAPAuthRequestItem{
		Request:    request,
		Priority:   priority,
		InsertTime: time.Now(),
	}
	heap.Push(&q.queue, item)
	q.notEmpty.Signal()
}

// Pop removes and returns the highest priority request from the LDAPAuthRequestQueue
// It blocks if the queue is empty
func (q *LDAPAuthRequestQueue) Pop() *bktype.LDAPAuthRequest {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	for q.queue.Len() == 0 {
		q.notEmpty.Wait()
	}

	item := heap.Pop(&q.queue).(*LDAPAuthRequestItem)
	return item.Request
}

// Push adds a request to the LuaRequestQueue with the given priority
func (q *LuaRequestQueue) Push(request *bktype.LuaRequest, priority int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	item := &LuaRequestItem{
		Request:    request,
		Priority:   priority,
		InsertTime: time.Now(),
	}
	heap.Push(&q.queue, item)
	q.notEmpty.Signal()
}

// Pop removes and returns the highest priority request from the LuaRequestQueue
// It blocks if the queue is empty
func (q *LuaRequestQueue) Pop() *bktype.LuaRequest {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	for q.queue.Len() == 0 {
		q.notEmpty.Wait()
	}

	item := heap.Pop(&q.queue).(*LuaRequestItem)
	return item.Request
}

// Global queue instances
var (
	LDAPQueue     = NewLDAPRequestQueue()
	LDAPAuthQueue = NewLDAPAuthRequestQueue()
	LuaQueue      = NewLuaRequestQueue()
)
