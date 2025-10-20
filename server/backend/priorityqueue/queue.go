package priorityqueue

import (
	"container/heap"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/stats"
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

// Len returns the number of items currently stored in the LDAPRequestPriorityQueue.
func (pq *LDAPRequestPriorityQueue) Len() int { return len(*pq) }

// Less determines the order of items in the priority queue by comparing their Priority and InsertTime fields.
func (pq *LDAPRequestPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if (*pq)[i].Priority != (*pq)[j].Priority {
		return (*pq)[i].Priority > (*pq)[j].Priority
	}

	// If priorities are equal, older requests come first
	return (*pq)[i].InsertTime.Before((*pq)[j].InsertTime)
}

// Swap exchanges the elements at indices i and j in the LDAPRequestPriorityQueue, updating their Index fields accordingly.
func (pq *LDAPRequestPriorityQueue) Swap(i, j int) {
	(*pq)[i], (*pq)[j] = (*pq)[j], (*pq)[i]
	(*pq)[i].Index = i
	(*pq)[j].Index = j
}

// Push adds a new LDAPRequestItem to the LDAPRequestPriorityQueue and sets its index to the next available position.
func (pq *LDAPRequestPriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*LDAPRequestItem)
	item.Index = n
	*pq = append(*pq, item)
}

// Pop removes and returns the highest-priority item from the LDAPRequestPriorityQueue, updating its Index field for safety.
func (pq *LDAPRequestPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]

	return item
}

// Len returns the number of items in the LDAPAuthRequestPriorityQueue.
func (pq *LDAPAuthRequestPriorityQueue) Len() int { return len(*pq) }

// Less determines the order of items in the LDAPAuthRequestPriorityQueue based on priority and insertion time.
func (pq *LDAPAuthRequestPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if (*pq)[i].Priority != (*pq)[j].Priority {
		return (*pq)[i].Priority > (*pq)[j].Priority
	}

	// If priorities are equal, older requests come first
	return (*pq)[i].InsertTime.Before((*pq)[j].InsertTime)
}

// Swap exchanges the elements at indices i and j in the LDAPAuthRequestPriorityQueue and updates their indices.
func (pq *LDAPAuthRequestPriorityQueue) Swap(i, j int) {
	(*pq)[i], (*pq)[j] = (*pq)[j], (*pq)[i]
	(*pq)[i].Index = i
	(*pq)[j].Index = j
}

// Push adds a new LDAPAuthRequestItem to the LDAPAuthRequestPriorityQueue and assigns its index.
func (pq *LDAPAuthRequestPriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*LDAPAuthRequestItem)
	item.Index = n
	*pq = append(*pq, item)
}

// Pop removes and returns the last item from the LDAPAuthRequestPriorityQueue, adjusting indices to maintain consistency.
func (pq *LDAPAuthRequestPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]

	return item
}

// Len returns the number of elements in the LuaRequestPriorityQueue.
func (pq *LuaRequestPriorityQueue) Len() int { return len(*pq) }

// Less determines the order of elements in the LuaRequestPriorityQueue based on priority and insertion time.
// Returns true if the element at index i should sort before the element at index j.
func (pq *LuaRequestPriorityQueue) Less(i, j int) bool {
	// Higher priority comes first
	if (*pq)[i].Priority != (*pq)[j].Priority {
		return (*pq)[i].Priority > (*pq)[j].Priority
	}

	// If priorities are equal, older requests come first
	return (*pq)[i].InsertTime.Before((*pq)[j].InsertTime)
}

// Swap swaps the elements with indexes i and j in the LuaRequestPriorityQueue and updates their respective Index fields.
func (pq *LuaRequestPriorityQueue) Swap(i, j int) {
	(*pq)[i], (*pq)[j] = (*pq)[j], (*pq)[i]
	(*pq)[i].Index = i
	(*pq)[j].Index = j
}

// Push adds a new LuaRequestItem to the LuaRequestPriorityQueue and assigns its index based on the current queue size.
func (pq *LuaRequestPriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*LuaRequestItem)
	item.Index = n
	*pq = append(*pq, item)
}

// Pop removes and returns the last element from the priority queue. It also resets the item's Index field for safety.
func (pq *LuaRequestPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // avoid memory leak
	item.Index = -1 // for safety
	*pq = old[0 : n-1]

	return item
}

// LDAPRequestQueue manages per-pool priority queues for LDAP requests
type LDAPRequestQueue struct {
	mutex     sync.Mutex
	poolNames map[string]bool
	pools     map[string]*struct {
		queue    LDAPRequestPriorityQueue
		notEmpty *sync.Cond
	}
	maxLen map[string]int // per-pool max queue length; 0 means unlimited
}

// LDAPAuthRequestQueue manages per-pool priority queues for LDAP auth requests
type LDAPAuthRequestQueue struct {
	mutex     sync.Mutex
	poolNames map[string]bool
	pools     map[string]*struct {
		queue    LDAPAuthRequestPriorityQueue
		notEmpty *sync.Cond
	}
	maxLen map[string]int // per-pool max queue length; 0 means unlimited
}

// LuaRequestQueue manages per-backend priority queues for Lua requests
type LuaRequestQueue struct {
	mutex        sync.Mutex
	backendNames map[string]bool
	backends     map[string]*struct {
		queue    LuaRequestPriorityQueue
		notEmpty *sync.Cond
	}
	maxLen map[string]int // per-backend max queue length; 0 means unlimited
}

// NewLDAPRequestQueue creates a new LDAPRequestQueue
func NewLDAPRequestQueue() *LDAPRequestQueue {
	q := &LDAPRequestQueue{
		poolNames: make(map[string]bool),
		pools: make(map[string]*struct {
			queue    LDAPRequestPriorityQueue
			notEmpty *sync.Cond
		}),
		maxLen: make(map[string]int),
	}

	return q
}

// NewLDAPAuthRequestQueue creates a new LDAPAuthRequestQueue
func NewLDAPAuthRequestQueue() *LDAPAuthRequestQueue {
	q := &LDAPAuthRequestQueue{
		poolNames: make(map[string]bool),
		pools: make(map[string]*struct {
			queue    LDAPAuthRequestPriorityQueue
			notEmpty *sync.Cond
		}),
		maxLen: make(map[string]int),
	}

	return q
}

// NewLuaRequestQueue creates a new LuaRequestQueue
func NewLuaRequestQueue() *LuaRequestQueue {
	q := &LuaRequestQueue{
		backendNames: make(map[string]bool),
		backends: make(map[string]*struct {
			queue    LuaRequestPriorityQueue
			notEmpty *sync.Cond
		}),
		maxLen: make(map[string]int),
	}

	return q
}

// AddPoolName adds a pool name to the LDAPRequestQueue
func (q *LDAPRequestQueue) AddPoolName(poolName string) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.poolNames[poolName] {
		return
	}

	q.poolNames[poolName] = true
	pq := make(LDAPRequestPriorityQueue, 0)

	heap.Init(&pq)

	q.pools[poolName] = &struct {
		queue    LDAPRequestPriorityQueue
		notEmpty *sync.Cond
	}{
		queue:    pq,
		notEmpty: sync.NewCond(&q.mutex),
	}
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

	if q.poolNames[poolName] {
		return
	}

	q.poolNames[poolName] = true
	pq := make(LDAPAuthRequestPriorityQueue, 0)

	heap.Init(&pq)

	q.pools[poolName] = &struct {
		queue    LDAPAuthRequestPriorityQueue
		notEmpty *sync.Cond
	}{
		queue:    pq,
		notEmpty: sync.NewCond(&q.mutex),
	}
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

// Push adds a request to the LDAPRequestQueue with the given priority, routed by PoolName
func (q *LDAPRequestQueue) Push(request *bktype.LDAPRequest, priority int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	poolName := request.PoolName
	p, ok := q.pools[poolName]
	if !ok {
		// initialize on the fly if not present
		pq := make(LDAPRequestPriorityQueue, 0)

		heap.Init(&pq)

		p = &struct {
			queue    LDAPRequestPriorityQueue
			notEmpty *sync.Cond
		}{
			queue:    pq,
			notEmpty: sync.NewCond(&q.mutex),
		}
		q.pools[poolName] = p
		q.poolNames[poolName] = true
	}

	// Drop early if the request context is already canceled
	if request.HTTPClientContext != nil {
		select {
		case <-request.HTTPClientContext.Done():
			stats.GetMetrics().GetLdapQueueDroppedTotal().WithLabelValues(poolName, "lookup").Inc()

			return
		default:
		}
	}

	// Drop on overflow if a max length is configured (>0)
	if maxLen, has := q.maxLen[poolName]; has && maxLen > 0 && p.queue.Len() >= maxLen {
		stats.GetMetrics().GetLdapQueueDroppedTotal().WithLabelValues(poolName, "lookup").Inc()

		return
	}

	item := &LDAPRequestItem{
		Request:    request,
		Priority:   priority,
		InsertTime: time.Now(),
	}

	heap.Push(&p.queue, item)
	// Update depth metric after enqueue
	stats.GetMetrics().GetLdapQueueDepth().WithLabelValues(poolName, "lookup").Set(float64(p.queue.Len()))
	p.notEmpty.Signal()
}

// Pop removes and returns the highest priority request from the LDAPRequestQueue for a specific pool
// It blocks if the queue for that pool is empty
func (q *LDAPRequestQueue) Pop(poolName string) *bktype.LDAPRequest {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	p, ok := q.pools[poolName]
	if !ok {
		pq := make(LDAPRequestPriorityQueue, 0)

		heap.Init(&pq)

		p = &struct {
			queue    LDAPRequestPriorityQueue
			notEmpty *sync.Cond
		}{
			queue:    pq,
			notEmpty: sync.NewCond(&q.mutex),
		}
		q.pools[poolName] = p
		q.poolNames[poolName] = true
	}

	for {
		for p.queue.Len() == 0 {
			p.notEmpty.Wait()
		}

		item := heap.Pop(&p.queue).(*LDAPRequestItem)

		// If the request context is already canceled, drop it and continue to next
		if item.Request != nil && item.Request.HTTPClientContext != nil {
			select {
			case <-item.Request.HTTPClientContext.Done():
				stats.GetMetrics().GetLdapQueueDroppedTotal().WithLabelValues(poolName, "lookup").Inc()
				// Update depth after drop and continue loop to fetch next item
				stats.GetMetrics().GetLdapQueueDepth().WithLabelValues(poolName, "lookup").Set(float64(p.queue.Len()))

				continue
			default:
			}
		}

		// Record queue wait time and new depth after dequeue
		stats.GetMetrics().GetLdapQueueWaitSeconds().WithLabelValues(poolName, "lookup").Observe(time.Since(item.InsertTime).Seconds())
		stats.GetMetrics().GetLdapQueueDepth().WithLabelValues(poolName, "lookup").Set(float64(p.queue.Len()))

		return item.Request
	}
}

// Push adds a request to the LDAPAuthRequestQueue with the given priority, routed by PoolName
func (q *LDAPAuthRequestQueue) Push(request *bktype.LDAPAuthRequest, priority int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	poolName := request.PoolName
	p, ok := q.pools[poolName]
	if !ok {
		pq := make(LDAPAuthRequestPriorityQueue, 0)

		heap.Init(&pq)

		p = &struct {
			queue    LDAPAuthRequestPriorityQueue
			notEmpty *sync.Cond
		}{
			queue:    pq,
			notEmpty: sync.NewCond(&q.mutex),
		}
		q.pools[poolName] = p
		q.poolNames[poolName] = true
	}

	// Drop early if the request context is already canceled
	if request.HTTPClientContext != nil {
		select {
		case <-request.HTTPClientContext.Done():
			stats.GetMetrics().GetLdapQueueDroppedTotal().WithLabelValues(poolName, "auth").Inc()

			return
		default:
		}
	}

	// Drop on overflow if a max length is configured (>0)
	if maxLen, has := q.maxLen[poolName]; has && maxLen > 0 && p.queue.Len() >= maxLen {
		stats.GetMetrics().GetLdapQueueDroppedTotal().WithLabelValues(poolName, "auth").Inc()

		return
	}

	item := &LDAPAuthRequestItem{
		Request:    request,
		Priority:   priority,
		InsertTime: time.Now(),
	}

	heap.Push(&p.queue, item)
	// Update depth metric after enqueue
	stats.GetMetrics().GetLdapQueueDepth().WithLabelValues(poolName, "auth").Set(float64(p.queue.Len()))
	p.notEmpty.Signal()
}

// Pop removes and returns the highest priority request from the LDAPAuthRequestQueue for a specific pool
// It blocks if the queue is empty
func (q *LDAPAuthRequestQueue) Pop(poolName string) *bktype.LDAPAuthRequest {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	p, ok := q.pools[poolName]
	if !ok {
		pq := make(LDAPAuthRequestPriorityQueue, 0)

		heap.Init(&pq)

		p = &struct {
			queue    LDAPAuthRequestPriorityQueue
			notEmpty *sync.Cond
		}{
			queue:    pq,
			notEmpty: sync.NewCond(&q.mutex),
		}
		q.pools[poolName] = p
		q.poolNames[poolName] = true
	}

	for {
		for p.queue.Len() == 0 {
			p.notEmpty.Wait()
		}

		item := heap.Pop(&p.queue).(*LDAPAuthRequestItem)

		// If the request context is already canceled, drop it and continue to next
		if item.Request != nil && item.Request.HTTPClientContext != nil {
			select {
			case <-item.Request.HTTPClientContext.Done():
				stats.GetMetrics().GetLdapQueueDroppedTotal().WithLabelValues(poolName, "auth").Inc()
				// Update depth after drop and continue loop to fetch next item
				stats.GetMetrics().GetLdapQueueDepth().WithLabelValues(poolName, "auth").Set(float64(p.queue.Len()))

				continue
			default:
			}
		}

		// Record queue wait time and new depth after dequeue
		stats.GetMetrics().GetLdapQueueWaitSeconds().WithLabelValues(poolName, "auth").Observe(time.Since(item.InsertTime).Seconds())
		stats.GetMetrics().GetLdapQueueDepth().WithLabelValues(poolName, "auth").Set(float64(p.queue.Len()))

		return item.Request
	}
}

// Push adds a request to the LuaRequestQueue with the given priority, routed by BackendName
func (q *LuaRequestQueue) Push(request *bktype.LuaRequest, priority int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	backendName := request.BackendName
	b, ok := q.backends[backendName]
	if !ok {
		pq := make(LuaRequestPriorityQueue, 0)

		heap.Init(&pq)

		b = &struct {
			queue    LuaRequestPriorityQueue
			notEmpty *sync.Cond
		}{
			queue:    pq,
			notEmpty: sync.NewCond(&q.mutex),
		}
		q.backends[backendName] = b
		q.backendNames[backendName] = true
	}

	// Drop early if the request context is already canceled
	if request.HTTPClientContext != nil && request.HTTPClientContext.Request != nil {
		select {
		case <-request.HTTPClientContext.Request.Context().Done():
			stats.GetMetrics().GetLuaQueueDroppedTotal().WithLabelValues(backendName).Inc()

			return
		default:
		}
	}

	// Drop on overflow if a max length is configured (>0)
	if maxLen, has := q.maxLen[backendName]; has && maxLen > 0 && b.queue.Len() >= maxLen {
		stats.GetMetrics().GetLuaQueueDroppedTotal().WithLabelValues(backendName).Inc()

		return
	}

	item := &LuaRequestItem{
		Request:    request,
		Priority:   priority,
		InsertTime: time.Now(),
	}

	heap.Push(&b.queue, item)
	// Update depth metric after enqueue
	stats.GetMetrics().GetLuaQueueDepth().WithLabelValues(backendName).Set(float64(b.queue.Len()))
	b.notEmpty.Signal()
}

// Pop removes and returns the highest priority request from the LuaRequestQueue for a specific backend
// It blocks if the queue is empty
func (q *LuaRequestQueue) Pop(backendName string) *bktype.LuaRequest {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	b, ok := q.backends[backendName]
	if !ok {
		pq := make(LuaRequestPriorityQueue, 0)

		heap.Init(&pq)

		b = &struct {
			queue    LuaRequestPriorityQueue
			notEmpty *sync.Cond
		}{
			queue:    pq,
			notEmpty: sync.NewCond(&q.mutex),
		}
		q.backends[backendName] = b
		q.backendNames[backendName] = true
	}

	for {
		for b.queue.Len() == 0 {
			b.notEmpty.Wait()
		}

		item := heap.Pop(&b.queue).(*LuaRequestItem)

		// If the request context is already canceled, drop it and continue to next
		if item.Request != nil && item.Request.HTTPClientContext != nil && item.Request.HTTPClientContext.Request != nil {
			select {
			case <-item.Request.HTTPClientContext.Request.Context().Done():
				stats.GetMetrics().GetLuaQueueDroppedTotal().WithLabelValues(backendName).Inc()
				// Update depth after drop and continue loop to fetch next item
				stats.GetMetrics().GetLuaQueueDepth().WithLabelValues(backendName).Set(float64(b.queue.Len()))

				continue
			default:
			}
		}

		// Record queue wait time and new depth after dequeue
		stats.GetMetrics().GetLuaQueueWaitSeconds().WithLabelValues(backendName).Observe(time.Since(item.InsertTime).Seconds())
		stats.GetMetrics().GetLuaQueueDepth().WithLabelValues(backendName).Set(float64(b.queue.Len()))

		return item.Request
	}
}

// Global queue instances
var (
	LDAPQueue     = NewLDAPRequestQueue()
	LDAPAuthQueue = NewLDAPAuthRequestQueue()
	LuaQueue      = NewLuaRequestQueue()
)

// SetMaxQueueLength sets the maximum queue length for a given LDAP pool in the lookup queue.
// A value <= 0 disables the limit (unlimited).
func (q *LDAPRequestQueue) SetMaxQueueLength(poolName string, n int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.maxLen == nil {
		q.maxLen = make(map[string]int)
	}

	q.maxLen[poolName] = n
}

// SetMaxQueueLength sets the maximum queue length for a given LDAP pool in the auth queue.
// A value <= 0 disables the limit (unlimited).
func (q *LDAPAuthRequestQueue) SetMaxQueueLength(poolName string, n int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.maxLen == nil {
		q.maxLen = make(map[string]int)
	}

	q.maxLen[poolName] = n
}

// SetMaxQueueLength sets the maximum queue length for a given Lua backend queue.
// A value <= 0 disables the limit (unlimited).
func (q *LuaRequestQueue) SetMaxQueueLength(backendName string, n int) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.maxLen == nil {
		q.maxLen = make(map[string]int)
	}

	q.maxLen[backendName] = n
}
