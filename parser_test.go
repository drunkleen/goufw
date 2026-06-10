package goufw

import (
	"net"
	"testing"
)

// ---------------------------------------------------------------------------
// parseIsEnabled
// ---------------------------------------------------------------------------

func TestParseIsEnabledActive(t *testing.T) {
	ok, err := parseIsEnabled("Status: active\n")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected active")
	}
}

func TestParseIsEnabledInactive(t *testing.T) {
	ok, err := parseIsEnabled("Status: inactive\n")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected inactive")
	}
}

func TestParseIsEnabledActiveWithExtraLines(t *testing.T) {
	raw := "Status: active\n\nTo                         Action      From\n"
	ok, err := parseIsEnabled(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected active")
	}
}

func TestParseIsEnabledEmpty(t *testing.T) {
	_, err := parseIsEnabled("")
	if err != errEmptyOutput {
		t.Fatalf("expected errEmptyOutput, got %v", err)
	}
}

func TestParseIsEnabledUnexpectedLine(t *testing.T) {
	_, err := parseIsEnabled("Something weird\n")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestParseIsEnabledWhitespace(t *testing.T) {
	ok, err := parseIsEnabled("  Status: active  \n")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected active with whitespace")
	}
}

// ---------------------------------------------------------------------------
// parsePortRules
// ---------------------------------------------------------------------------

const portRulesBasic = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8080/udp                   DENY IN     Anywhere
[ 3] 443/tcp                    ALLOW IN    Anywhere
[ 4] 53/udp                     ALLOW IN    Anywhere
`

func TestParsePortRulesBasic(t *testing.T) {
	rules, err := parsePortRules(portRulesBasic)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	checkPortRule(t, rules, 22, ProtocolTCP, RuleStatusAllowed)
	checkPortRule(t, rules, 8080, ProtocolUDP, RuleStatusDenied)
	checkPortRule(t, rules, 443, ProtocolTCP, RuleStatusAllowed)
	checkPortRule(t, rules, 53, ProtocolUDP, RuleStatusAllowed)
}

func checkPortRule(t *testing.T, rules []PortRule, port uint16, proto Protocol, status RuleStatus) {
	t.Helper()
	for _, r := range rules {
		if r.Port == port && r.Protocol == proto {
			if r.Status != status {
				t.Fatalf("port %d/%s: expected %v, got %v", port, proto, status, r.Status)
			}
			return
		}
	}
	t.Fatalf("port %d/%s not found", port, proto)
}

func TestParsePortRulesEmpty(t *testing.T) {
	rules, err := parsePortRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestParsePortRulesV6(t *testing.T) {
	raw := `[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 3] 8080/udp (v6)              DENY IN     Anywhere (v6)
`
	rules, err := parsePortRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	checkPortRule(t, rules, 22, ProtocolTCP, RuleStatusAllowed)
	checkPortRule(t, rules, 8080, ProtocolUDP, RuleStatusDenied)
}

func TestParsePortRulesMalformed(t *testing.T) {
	raw := `[ 1] Not a real rule
[ 2] 22/tcp                     ALLOW IN    Anywhere
random garbage
`
	rules, err := parsePortRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Port != 22 || rules[0].Protocol != ProtocolTCP || rules[0].Status != RuleStatusAllowed {
		t.Fatal("expected 22/tcp allowed")
	}
}

func TestParsePortRulesDuplicates(t *testing.T) {
	raw := `[ 1] 22/tcp  ALLOW IN  Anywhere
[ 2] 22/tcp  ALLOW IN  Anywhere
`
	rules, err := parsePortRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 duplicates, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// parseIPRules
// ---------------------------------------------------------------------------

const ipRulesBasic = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   ALLOW IN    192.168.1.10
[ 2] Anywhere                   DENY IN     10.0.0.5
[ 3] Anywhere                   ALLOW IN    2001:db8::1
[ 4] Anywhere                   DENY IN     ::1
`

func TestParseIPRulesBasic(t *testing.T) {
	rules, err := parseIPRules(ipRulesBasic)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	checkIPRule(t, rules, "192.168.1.10", RuleStatusAllowed)
	checkIPRule(t, rules, "10.0.0.5", RuleStatusDenied)
	checkIPRule(t, rules, "2001:db8::1", RuleStatusAllowed)
	checkIPRule(t, rules, "::1", RuleStatusDenied)
}

func checkIPRule(t *testing.T, rules []IpRule, ip string, status RuleStatus) {
	t.Helper()
	for _, r := range rules {
		if r.IP.Equal(parseIP(ip)) {
			if r.Status != status {
				t.Fatalf("IP %s: expected %v, got %v", ip, status, r.Status)
			}
			return
		}
	}
	t.Fatalf("IP %s not found", ip)
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func TestParseIPRulesEmpty(t *testing.T) {
	rules, err := parseIPRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseIPRulesSkipsPortLines(t *testing.T) {
	raw := `[ 1] 22/tcp  ALLOW IN  Anywhere
[ 2] Anywhere  ALLOW IN  192.168.1.10
`
	rules, err := parseIPRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 IP rule, got %d", len(rules))
	}
}

// ---------------------------------------------------------------------------
// findPortStatus
// ---------------------------------------------------------------------------

func TestFindPortStatusTCPAllowed(t *testing.T) {
	rules, _ := parsePortRules("[ 1] 22/tcp  ALLOW IN  Anywhere\n")
	if s := findPortStatus(rules, 22, ProtocolTCP); s != RuleStatusAllowed {
		t.Fatalf("expected Allowed, got %v", s)
	}
}

func TestFindPortStatusUDPDenied(t *testing.T) {
	rules, _ := parsePortRules("[ 1] 8080/udp  DENY IN  Anywhere\n")
	if s := findPortStatus(rules, 8080, ProtocolUDP); s != RuleStatusDenied {
		t.Fatalf("expected Denied, got %v", s)
	}
}

func TestFindPortStatusNone(t *testing.T) {
	rules, _ := parsePortRules("[ 1] 22/tcp  ALLOW IN  Anywhere\n")
	if s := findPortStatus(rules, 9999, ProtocolTCP); s != RuleStatusNone {
		t.Fatalf("expected None, got %v", s)
	}
}

func TestFindPortStatusBothBothAllowed(t *testing.T) {
	raw := "[ 1] 22/tcp  ALLOW IN  Anywhere\n[ 2] 22/udp  ALLOW IN  Anywhere\n"
	rules, _ := parsePortRules(raw)
	if s := findPortStatus(rules, 22, ProtocolBoth); s != RuleStatusAllowed {
		t.Fatalf("expected Allowed, got %v", s)
	}
}

func TestFindPortStatusBothMixedReturnsNone(t *testing.T) {
	raw := "[ 1] 22/tcp  ALLOW IN  Anywhere\n[ 2] 22/udp  DENY IN  Anywhere\n"
	rules, _ := parsePortRules(raw)
	if s := findPortStatus(rules, 22, ProtocolBoth); s != RuleStatusNone {
		t.Fatalf("expected None, got %v", s)
	}
}

// ---------------------------------------------------------------------------
// findIPStatus
// ---------------------------------------------------------------------------

func TestFindIPStatusAllowed(t *testing.T) {
	raw := "[ 1] Anywhere  ALLOW IN  192.168.1.10\n"
	rules, _ := parseIPRules(raw)
	if s := findIPStatus(rules, parseIP("192.168.1.10"), ProtocolBoth); s != RuleStatusAllowed {
		t.Fatalf("expected Allowed, got %v", s)
	}
}

func TestFindIPStatusNone(t *testing.T) {
	rules, _ := parseIPRules("[ 1] Anywhere  ALLOW IN  192.168.1.10\n")
	if s := findIPStatus(rules, parseIP("127.0.0.1"), ProtocolBoth); s != RuleStatusNone {
		t.Fatalf("expected None, got %v", s)
	}
}
