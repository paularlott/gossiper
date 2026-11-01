package server

import (
	"strings"

	"github.com/paularlott/logger"
)

// applyExtraDirectives applies FrankenPHP's MERCURE_EXTRA_DIRECTIVES (Caddyfile directives of its mercure block, one
// a line) to the settings they have equivalents for, where the setting was not given another way: a deployment moving
// from FrankenPHP's hub keeps its settings. Others are logged and ignored.
func applyExtraDirectives(s *Settings, directives string, log logger.Logger) {
	def := Defaults()
	for _, line := range strings.Split(directives, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "{" || f[0] == "}" || strings.HasPrefix(f[0], "#") {
			continue
		}
		args := f[1:]
		for i, a := range args {
			args[i] = strings.Trim(a, `"'`)
		}
		one := func(to *string, unset string) {
			if len(args) > 0 && *to == unset {
				*to = args[0]
			}
		}
		switch f[0] {
		case "anonymous":
			s.Anonymous = true
		case "subscriptions":
			s.Subscriptions = true
		case "cors_origins":
			if len(s.CORSOrigins) == 0 {
				s.CORSOrigins = args
			}
		case "publish_origins":
			if len(s.PublishOrigins) == 0 {
				s.PublishOrigins = args
			}
		case "cookie_name":
			one(&s.CookieName, "")
		case "heartbeat":
			one(&s.Heartbeat, def.Heartbeat)
		case "write_timeout":
			one(&s.WriteTimeout, def.WriteTimeout)
		default:
			log.Warn("MERCURE_EXTRA_DIRECTIVES: directive not supported, ignored", "directive", f[0])
		}
	}
}
