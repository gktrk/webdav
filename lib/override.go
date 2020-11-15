package lib

import (
       "strings"
)

type Override struct {
	Auth     	bool
	User		*User
}

func (o Override) MatchURL(url string) bool {
	rule := o.User.Rules[0]
	if rule.Regex {
		if rule.Regexp.MatchString(url) {
			return true
		}
	}  else if strings.Compare(url, rule.Path) == 0 {
		return true
	}

	return false
}
