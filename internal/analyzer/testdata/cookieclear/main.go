// A fixture for the cookie-clearing signal. Logout clears the refresh cookie
// through a helper, h.setRefreshCookie(c, "", -1), so at the SetCookie call the
// max-age is the helper's parameter and the -1 lives at the caller — the case
// the detector must resolve. Login calls the same helper with a positive
// max-age and must not be flagged.
package main

import "github.com/gin-gonic/gin"

type handler struct{}

func (h handler) setRefreshCookie(c *gin.Context, value string, maxAge int) {
	c.SetCookie("refresh", value, maxAge, "/", "", true, true)
}

func (h handler) Logout(c *gin.Context) {
	h.setRefreshCookie(c, "", -1)
}

func (h handler) Login(c *gin.Context) {
	h.setRefreshCookie(c, "tok", 3600)
}

func (h handler) GetThing(c *gin.Context) {
	c.JSON(200, gin.H{"ok": true})
}

func main() {
	h := handler{}
	r := gin.New()
	r.POST("/logout", h.Logout)
	r.POST("/login", h.Login)
	r.GET("/thing", h.GetThing)
	_ = r
}
