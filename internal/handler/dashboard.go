package handler

import (
	"net/http"
)

func DashboardHandler(res http.ResponseWriter, req *http.Request) {
	http.ServeFile(res, req, "web/page/dashboard.html")
}
