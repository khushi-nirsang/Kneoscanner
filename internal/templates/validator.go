package templates

import (
	"fmt"
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

func ValidateTemplate(t Template) error {

	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("template missing id")
	}

	if strings.TrimSpace(t.Info.Name) == "" {
		return fmt.Errorf("template missing name")
	}

	if !validSeverities[strings.ToLower(strings.TrimSpace(t.Info.Severity))] {
		return fmt.Errorf(
			"invalid severity '%s'",
			t.Info.Severity,
		)
	}

	if len(t.Requests) == 0 {
		return fmt.Errorf("template has no requests")
	}

	for reqIndex, req := range t.Requests {

		if !validMethods[strings.ToUpper(strings.TrimSpace(req.Method))] {
			return fmt.Errorf(
				"request %d has unsupported method '%s'",
				reqIndex,
				req.Method,
			)
		}

		if req.MatchersCondition != "" &&
			req.MatchersCondition != "and" &&
			req.MatchersCondition != "or" {

			return fmt.Errorf(
				"request %d has invalid matchers-condition '%s'",
				reqIndex,
				req.MatchersCondition,
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

		for matcherIndex, matcher := range req.Matchers {

			if matcher.Condition != "" &&
				matcher.Condition != "and" &&
				matcher.Condition != "or" {

				return fmt.Errorf(
					"request %d matcher %d has invalid condition '%s'",
					reqIndex,
					matcherIndex,
					matcher.Condition,
				)
			}

			switch strings.ToLower(strings.TrimSpace(matcher.Type)) {

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