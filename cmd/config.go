package cmd

import (
	"errors"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/hacdias/webdav/v3/lib"
	"github.com/spf13/pflag"
	v "github.com/spf13/viper"
	"golang.org/x/net/webdav"
)

func parseRules(raw []interface{}) []*lib.Rule {
	rules := []*lib.Rule{}

	for _, v := range raw {
		if r, ok := v.(map[interface{}]interface{}); ok {
			rule := &lib.Rule{
				Regex: false,
				Allow: false,
				Path:  "",
			}

			if regex, ok := r["regex"].(bool); ok {
				rule.Regex = regex
			}

			if allow, ok := r["allow"].(bool); ok {
				rule.Allow = allow
			}

			path, ok := r["path"].(string)
			if !ok {
				continue
			}

			if rule.Regex {
				rule.Regexp = regexp.MustCompile(path)
			} else {
				rule.Path = path
			}

			rules = append(rules, rule)
		}
	}

	return rules
}

func loadFromEnv(v string) (string, error) {
	v = strings.TrimPrefix(v, "{env}")
	if v == "" {
		return "", errors.New("no environment variable specified")
	}

	v = os.Getenv(v)
	if v == "" {
		return "", errors.New("the environment variable is empty")
	}

	return v, nil
}

func parseUsers(raw []interface{}, c *lib.Config) {
	var err error
	for _, v := range raw {
		if u, ok := v.(map[interface{}]interface{}); ok {
			extra_passwords := []string{}
			username, ok := u["username"].(string)
			if !ok {
				log.Fatal("user needs an username")
			}

			if strings.HasPrefix(username, "{env}") {
				username, err = loadFromEnv(username)
				checkErr(err)
			}

			password, ok := u["password"].(string)
			if !ok {
				password = ""

				if numPwd, ok := u["password"].(int); ok {
					password = strconv.Itoa(numPwd)
				}
			}

			if strings.HasPrefix(password, "{env}") {
				password, err = loadFromEnv(password)
				checkErr(err)
			}

			if raw_extra_passwords, ok := u["extra_passwords"].([]interface{}); ok {
				for _, password := range raw_extra_passwords {
					extra_passwords = append(extra_passwords, password.(string))
				}
			}

			user := &lib.User{
				Username: username,
				Password: password,
				ExtraPasswords: extra_passwords,
				Scope:    c.User.Scope,
				Modify:   c.User.Modify,
				Rules:    c.User.Rules,
			}

			if scope, ok := u["scope"].(string); ok {
				user.Scope = scope
			}

			if modify, ok := u["modify"].(bool); ok {
				user.Modify = modify
			}

			if rules, ok := u["rules"].([]interface{}); ok {
				user.Rules = parseRules(rules)
			}

			user.Handler = &webdav.Handler{
				Prefix:     c.User.Handler.Prefix,
				FileSystem: webdav.Dir(user.Scope),
				LockSystem: webdav.NewMemLS(),
			}

			c.Users[username] = user
		}
	}
}

func parseCors(cfg map[string]interface{}, c *lib.Config) {
	cors := lib.CorsCfg{
		Enabled:     cfg["enabled"].(bool),
		Credentials: cfg["credentials"].(bool),
	}

	cors.AllowedHeaders = corsProperty("allowed_headers", cfg)
	cors.AllowedHosts = corsProperty("allowed_hosts", cfg)
	cors.AllowedMethods = corsProperty("allowed_methods", cfg)
	cors.ExposedHeaders = corsProperty("exposed_headers", cfg)

	c.Cors = cors
}

func corsProperty(property string, cfg map[string]interface{}) []string {
	var def []string

	if property == "exposed_headers" {
		def = []string{}
	} else {
		def = []string{"*"}
	}

	if allowed, ok := cfg[property].([]interface{}); ok {
		items := make([]string, len(allowed))

		for idx, a := range allowed {
			items[idx] = a.(string)
		}

		if len(items) == 0 {
			return def
		}

		return items
	}

	return def
}


func parseOverrides(raw []interface{}, c *lib.Config) {
	for _, v := range raw {
		if o, ok := v.(map[interface{}]interface{}); ok {
			override := &lib.Override{
				Auth: c.Auth,
				User: &lib.User{
					Scope: c.User.Scope,
					Modify: c.User.Modify,
					Rules: []*lib.Rule{},
					Handler: c.User.Handler,
				},
			}
			rule := &lib.Rule{
				Allow: false,
			}

			if auth, ok := o["auth"].(bool); ok {
				override.Auth = auth
			}

			if modify, ok := o["modify"].(bool); ok {
				override.User.Modify = modify
			}

			if allow, ok := o["allow"].(bool); ok {
				rule.Allow = allow
			}

			path, ok := o["path"].(string)
			if !ok {
				continue
			}

			if regex, ok := o["regex"].(bool); ok {
				rule.Regex = regex
			}

			if rule.Regex {
				rule.Regexp = regexp.MustCompile(path)
			} else {
				rule.Path = path
			}

			override.User.Rules = append(override.User.Rules, rule)
			c.Overrides = append(c.Overrides, override)
		}
	}
}

func readConfig(flags *pflag.FlagSet) *lib.Config {
	cfg := &lib.Config{
		User: &lib.User{
			Scope:  getOpt(flags, "scope"),
			Modify: getOptB(flags, "modify"),
			Rules:  []*lib.Rule{},
			Handler: &webdav.Handler{
				Prefix:     getOpt(flags, "prefix"),
				FileSystem: webdav.Dir(getOpt(flags, "scope")),
				LockSystem: webdav.NewMemLS(),
			},
		},
		Auth: getOptB(flags, "auth"),
		Cors: lib.CorsCfg{
			Enabled:     false,
			Credentials: false,
		},
		Users: map[string]*lib.User{},
		Overrides: []*lib.Override{},
	}

	rawRules := v.Get("rules")
	if rules, ok := rawRules.([]interface{}); ok {
		cfg.User.Rules = parseRules(rules)
	}

	rawUsers := v.Get("users")
	if users, ok := rawUsers.([]interface{}); ok {
		parseUsers(users, cfg)
	}

	rawCors := v.Get("cors")
	if cors, ok := rawCors.(map[string]interface{}); ok {
		parseCors(cors, cfg)
	}

	rawOverrides := v.Get("overrides")
	if overrides, ok := rawOverrides.([]interface{}); ok {
		parseOverrides(overrides, cfg)
	}

	if len(cfg.Users) != 0 && !cfg.Auth {
		log.Print("Users will be ignored due to auth=false")
	}

	return cfg
}
