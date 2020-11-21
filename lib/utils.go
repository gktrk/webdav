package lib

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func checkPassword(saved, input string) bool {
	if strings.HasPrefix(saved, "{bcrypt}") {
		savedPassword := strings.TrimPrefix(saved, "{bcrypt}")
		return bcrypt.CompareHashAndPassword([]byte(savedPassword), []byte(input)) == nil
	} else if strings.HasPrefix(saved, "{otpauth}") {
		otp_string := strings.TrimPrefix(saved, "{otpauth}")
		if key,_ := otp.NewKeyFromURL(otp_string); key != nil {
			if totp.Validate(input, key.Secret()) {
				return true
			}
		}
	}

	return saved == input
}

func isAllowedHost(allowedHosts []string, origin string) bool {
	for _, host := range allowedHosts {
		if host == origin {
			return true
		}
	}
	return false
}
