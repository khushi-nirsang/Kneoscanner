package fingerprint

import (
	"strings"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

type Fingerprint struct {
	Tech     []string
	CMS      string
	Server   string
	Language string
}

func Detect(resp *utils.Response) *Fingerprint {
	fp := &Fingerprint{}

	body := strings.ToLower(resp.BodyContent)
	headerServer := strings.ToLower(resp.Header.Get("Server"))

	// Server
	if strings.Contains(headerServer, "apache") {
		fp.Server = "Apache"
		fp.Tech = append(fp.Tech, "apache")
	} else if strings.Contains(headerServer, "nginx") {
		fp.Server = "Nginx"
		fp.Tech = append(fp.Tech, "nginx")
	}

	// CMS
	if strings.Contains(body, "wp-content") || strings.Contains(body, "wordpress") {
		fp.CMS = "WordPress"
		fp.Tech = append(fp.Tech, "wordpress")
	} else if strings.Contains(body, "joomla") {
		fp.CMS = "Joomla"
		fp.Tech = append(fp.Tech, "joomla")
	}

	// Language
	if strings.Contains(body, "php") || strings.Contains(headerServer, "php") {
		fp.Language = "PHP"
		fp.Tech = append(fp.Tech, "php")
	}

	return fp
}