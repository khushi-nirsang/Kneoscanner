package templates

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var validSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

var validMethods = map[string]bool{
	"GET":    true,
	"POST":   true,
	"PUT":    true,
	"DELETE": true,
	"PATCH":  true,
	"HEAD":   true,
}

var validConfidence = map[string]bool{"": true, "potential": true, "firm": true, "confirmed": true}
var validRisks = map[string]bool{"": true, "passive": true, "safe": true, "active": true, "intrusive": true}

func ValidateTemplate(t Template) error {

	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("template missing id")
	}

	if strings.TrimSpace(t.Info.Name) == "" {
		return fmt.Errorf("template missing name")
	}

	if !validSeverities[strings.ToLower(
		strings.TrimSpace(t.Info.Severity),
	)] {
		return fmt.Errorf(
			"invalid severity '%s'",
			t.Info.Severity,
		)
	}

	if len(t.Requests) == 0 {
		return fmt.Errorf("template has no requests")
	}
	if !validConfidence[strings.ToLower(strings.TrimSpace(t.Info.Confidence))] {
		return fmt.Errorf("invalid confidence %q; use potential, firm, or confirmed", t.Info.Confidence)
	}
	if !validRisks[strings.ToLower(strings.TrimSpace(t.Info.Risk))] {
		return fmt.Errorf("invalid risk %q; use passive, safe, active, or intrusive", t.Info.Risk)
	}
	if t.Info.CVSSScore < 0 || t.Info.CVSSScore > 10 {
		return fmt.Errorf("invalid CVSS score %.2f; use 0 through 10", t.Info.CVSSScore)
	}

	for reqIndex, req := range t.Requests {

		if !validMethods[strings.ToUpper(
			strings.TrimSpace(req.Method),
		)] {
			return fmt.Errorf(
				"request %d has unsupported method '%s'",
				reqIndex,
				req.Method,
			)
		}

		if len(req.Path) == 0 {
			return fmt.Errorf(
				"request %d has no paths",
				reqIndex,
			)
		}

		if len(req.Matchers) == 0 {
			return fmt.Errorf(
				"request %d has no matchers",
				reqIndex,
			)
		}
		condition := strings.ToLower(strings.TrimSpace(req.MatchersCondition))
		if condition != "" && condition != "and" && condition != "or" {
			return fmt.Errorf("request %d has invalid matchers-condition %q", reqIndex, req.MatchersCondition)
		}

		for _, payloadFile := range req.Payloads {

			if payloadFile == "" {
				continue
			}

			if _, err := os.Stat(payloadFile); err != nil {

				return fmt.Errorf(
					"payload file not found: %s",
					payloadFile,
				)
			}
		}

		for matcherIndex, matcher := range req.Matchers {
			part := strings.ToLower(strings.TrimSpace(matcher.Part))
			if part != "" && part != "body" && part != "header" {
				return fmt.Errorf("request %d matcher %d has unsupported part %q", reqIndex, matcherIndex, matcher.Part)
			}
			matcherCondition := strings.ToLower(strings.TrimSpace(matcher.Condition))
			if matcherCondition != "" && matcherCondition != "and" && matcherCondition != "or" {
				return fmt.Errorf("request %d matcher %d has invalid condition %q", reqIndex, matcherIndex, matcher.Condition)
			}

			switch strings.ToLower(
				strings.TrimSpace(matcher.Type),
			) {

			case "word":

				if len(matcher.Words) == 0 {

					return fmt.Errorf(
						"request %d matcher %d has no words",
						reqIndex,
						matcherIndex,
					)
				}

			case "status":

				if len(matcher.Status) == 0 {

					return fmt.Errorf(
						"request %d matcher %d has no status codes",
						reqIndex,
						matcherIndex,
					)
				}

			case "regex":

				if len(matcher.Regex) == 0 {

					return fmt.Errorf(
						"request %d matcher %d has no regex",
						reqIndex,
						matcherIndex,
					)
				}
				for _, pattern := range matcher.Regex {
					if _, err := regexp.Compile(pattern); err != nil {
						return fmt.Errorf("request %d matcher %d has invalid regex %q: %w", reqIndex, matcherIndex, pattern, err)
					}
				}

			default:

				return fmt.Errorf(
					"request %d matcher %d has unsupported type '%s'",
					reqIndex,
					matcherIndex,
					matcher.Type,
				)
			}
		}
	}

	return nil
}
