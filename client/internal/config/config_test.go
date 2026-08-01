package config

import "testing"

func TestValidateListenSecurity(t *testing.T) {
	base := Config{ListenAddr: "127.0.0.1:7410", AllowedCIDRs: []string{"127.0.0.0/8"}}
	if err := base.ValidateListenSecurity(); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]Config{
		"unspecified":                  {ListenAddr: "0.0.0.0:7410", AllowedCIDRs: []string{"0.0.0.0/0"}},
		"lan requires explicit opt-in": {ListenAddr: "192.0.2.10:7410", AllowedCIDRs: []string{"192.0.2.0/24"}},
		"lan requires tls":             {ListenAddr: "192.0.2.10:7410", AllowLAN: true, AllowedCIDRs: []string{"192.0.2.0/24"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cfg.ValidateListenSecurity(); err == nil {
				t.Fatal("expected listener security validation failure")
			}
		})
	}
	validLAN := Config{ListenAddr: "192.0.2.10:7410", AllowLAN: true, AllowedCIDRs: []string{"192.0.2.0/24"}, TLSCertFile: "/etc/client.crt", TLSKeyFile: "/etc/client.key"}
	if err := validLAN.ValidateListenSecurity(); err != nil {
		t.Fatal(err)
	}
}
