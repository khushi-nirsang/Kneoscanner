package fingerprint

import (
	"strings"

	"github.com/khushi-nirsang/neoscanner/internal/utils"
)

type Fingerprint struct {
	Server       string   `json:"server"`
	CMS          string   `json:"cms"`
	Language     string   `json:"language"`
	Technologies []string `json:"technologies"`
}

func Detect(resp *utils.Response) *Fingerprint {

	fp := &Fingerprint{
		Technologies: make([]string, 0),
	}

	if resp == nil || resp.Response == nil {
		return fp
	}

	body := strings.ToLower(resp.BodyContent)

	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))

	// ----------------------------------
	// Server Detection
	// ----------------------------------

	switch {

	case strings.Contains(serverHeader, "apache"):
		fp.Server = "Apache"
		fp.addTech("apache")

	case strings.Contains(serverHeader, "nginx"):
		fp.Server = "Nginx"
		fp.addTech("nginx")

	case strings.Contains(serverHeader, "iis"):
		fp.Server = "IIS"
		fp.addTech("iis")

	case strings.Contains(serverHeader, "openresty"):
		fp.Server = "OpenResty"
		fp.addTech("openresty")
	}

	// ----------------------------------
	// CMS Detection
	// ----------------------------------

	switch {

	case strings.Contains(body, "wp-content"),
		strings.Contains(body, "wp-includes"),
		strings.Contains(body, "wordpress"):

		fp.CMS = "WordPress"
		fp.addTech("wordpress")

	case strings.Contains(body, "joomla"):

		fp.CMS = "Joomla"
		fp.addTech("joomla")

	case strings.Contains(body, "drupal"):

		fp.CMS = "Drupal"
		fp.addTech("drupal")
	}

	// ----------------------------------
	// Language Detection
	// ----------------------------------

	if strings.Contains(poweredBy, "php") ||
		strings.Contains(body, ".php") {

		fp.Language = "PHP"
		fp.addTech("php")
	}

	if strings.Contains(poweredBy, "asp.net") {
		fp.Language = "ASP.NET"
		fp.addTech("asp.net")
	}

	if strings.Contains(poweredBy, "express") {
		fp.Language = "NodeJS"
		fp.addTech("nodejs")
		fp.addTech("express")
	}

	// ----------------------------------
	// Framework Detection
	// ----------------------------------

	if strings.Contains(body, "laravel_session") ||
		strings.Contains(body, "laravel") {
		fp.addTech("laravel")
	}

	if strings.Contains(body, "csrftoken") ||
		strings.Contains(body, "django") {
		fp.addTech("django")
	}

	if strings.Contains(body, "__viewstate") {
		fp.addTech("asp.net")
	}

	if strings.Contains(body, "_next/static") {
		fp.addTech("nextjs")
	}

	if strings.Contains(body, "__nuxt") {
		fp.addTech("nuxtjs")
	}

	if strings.Contains(body, "react") {
		fp.addTech("react")
	}

	if strings.Contains(body, "ng-version") {
		fp.addTech("angular")
	}

	if strings.Contains(body, "vue") {
		fp.addTech("vue")
	}

	// ----------------------------------
	// Security / Infra Detection
	// ----------------------------------

	if resp.Header.Get("CF-Ray") != "" {
		fp.addTech("cloudflare")
	}

	if resp.Header.Get("X-Amz-Cf-Id") != "" {
		fp.addTech("cloudfront")
	}

	if resp.Header.Get("X-Powered-By") != "" {
		fp.addTech("powered-by-header")
	}

	return fp
}

func (fp *Fingerprint) addTech(tech string) {

	tech = strings.TrimSpace(strings.ToLower(tech))

	if tech == "" {
		return
	}

	for _, existing := range fp.Technologies {
		if existing == tech {
			return
		}
	}

	fp.Technologies = append(fp.Technologies, tech)
}