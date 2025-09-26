package auth

import (
	"net/http"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

type Handler struct{ cfg config.File }

func New(cfg config.File) *Handler { return &Handler{cfg: cfg} }

func (h *Handler) Register(r gin.IRouter) {
	ag := r.Group("/" + definitions.CatAuth)

	ag.GET("/"+definitions.ServBasic, h.basic)
	ag.POST("/"+definitions.ServBasic, h.basic)
	ag.GET("/"+definitions.ServJSON, h.json)
	ag.POST("/"+definitions.ServJSON, h.json)
	ag.GET("/"+definitions.ServHeader, h.header)
	ag.POST("/"+definitions.ServHeader, h.header)
	ag.GET("/"+definitions.ServNginx, h.nginx)
	ag.POST("/"+definitions.ServNginx, h.nginx)
	ag.POST("/"+definitions.ServSaslauthd, h.saslAuthd)
}

func (h *Handler) basic(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthBasicDisabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	h.process(c, definitions.ServBasic)
}

func (h *Handler) json(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthJSONDisabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	h.process(c, definitions.ServJSON)
}

func (h *Handler) header(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthHeaderDisabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	h.process(c, definitions.ServHeader)
}

func (h *Handler) nginx(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthNginxDisabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	h.process(c, definitions.ServNginx)
}

func (h *Handler) saslAuthd(c *gin.Context) {
	if h.cfg.GetServer().GetEndpoint().IsAuthSASLAuthdDisabled() {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	// Same pre-processing flow but use the specific SASL handler
	auth := core.NewAuthStateWithSetup(c)
	if auth == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	defer core.PutAuthState(auth)
	if reject := auth.PreproccessAuthRequest(c); reject { //nolint:gosimple // match existing signature
		return
	}
	auth.HandleSASLAuthdAuthentication(c)
}

func (h *Handler) process(c *gin.Context, service string) {
	auth := core.NewAuthStateWithSetup(c)
	if auth == nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	defer core.PutAuthState(auth)
	if reject := auth.PreproccessAuthRequest(c); reject {
		return
	}
	auth.HandleAuthentication(c)
}
