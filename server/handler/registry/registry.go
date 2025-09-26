package registry

import "github.com/gin-gonic/gin"

// Registrar is the common interface every handler module implements to register its routes
// on a gin router or router group.
type Registrar interface {
	Register(r gin.IRouter)
}

// GroupRegistrar allows a module to expose a base path and register using a RouterGroup.
// Optional helper if a module prefers grouping under a fixed base string.
type GroupRegistrar interface {
	Base() string
	RegisterGroup(g *gin.RouterGroup)
}
