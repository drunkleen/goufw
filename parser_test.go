package goufw

import (
	"net/netip"
	"testing"
)

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

const sampleStatus = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 8080/udp                   DENY IN     Anywhere
[ 3] 443/tcp                    ALLOW IN    Anywhere
[ 4] 53/udp                     ALLOW IN    Anywhere
`

func TestParsePortRules(t *testing.T) {
	rules, err := parseRules(sampleStatus)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	checkRulePort(t, rules, 22, TCP, StatusAllowed, RuleKindPort)
	checkRulePort(t, rules, 8080, UDP, StatusDenied, RuleKindPort)
	checkRulePort(t, rules, 443, TCP, StatusAllowed, RuleKindPort)
	checkRulePort(t, rules, 53, UDP, StatusAllowed, RuleKindPort)
}

func checkRulePort(t *testing.T, rules []Rule, port uint16, proto Protocol, status Status, kind RuleKind) {
	t.Helper()
	for _, r := range rules {
		if r.Kind == kind && r.Port == port && r.Protocol == proto {
			if r.Status != status {
				t.Fatalf("port %d/%s: expected %v, got %v", port, proto, status, r.Status)
			}
			return
		}
	}
	t.Fatalf("port %d/%s not found", port, proto)
}

func TestParseRulesEmpty(t *testing.T) {
	rules, err := parseRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(rules))
	}
}

func TestParseRulesV6(t *testing.T) {
	raw := `[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
[ 3] 8080/udp (v6)              DENY IN     Anywhere (v6)
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(rules))
	}
	checkRulePort(t, rules, 22, TCP, StatusAllowed, RuleKindPort)
	checkRulePort(t, rules, 8080, UDP, StatusDenied, RuleKindPort)
}

func TestParseIPRules(t *testing.T) {
	raw := `[ 1] Anywhere                   ALLOW IN    192.168.1.10
[ 2] Anywhere                   DENY IN     10.0.0.5
[ 3] Anywhere                   ALLOW IN    2001:db8::1
[ 4] Anywhere                   DENY IN     ::1
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	checkRuleIP(t, rules, "192.168.1.10", StatusAllowed, RuleKindIP)
	checkRuleIP(t, rules, "10.0.0.5", StatusDenied, RuleKindIP)
	checkRuleIP(t, rules, "2001:db8::1", StatusAllowed, RuleKindIP)
	checkRuleIP(t, rules, "::1", StatusDenied, RuleKindIP)
}

func checkRuleIP(t *testing.T, rules []Rule, ip string, status Status, kind RuleKind) {
	t.Helper()
	parsed := netip.MustParseAddr(ip)
	for _, r := range rules {
		if r.Kind == kind && r.IP == parsed {
			if r.Status != status {
				t.Fatalf("IP %s: expected %v, got %v", ip, status, r.Status)
			}
			return
		}
	}
	t.Fatalf("IP %s not found", ip)
}

func TestParseIPPortRules(t *testing.T) {
	raw := `[ 1] 22/tcp                     ALLOW IN    192.168.1.10
[ 2] 443/tcp                    DENY IN     10.0.0.5
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	checkRuleIPPort(t, rules, "192.168.1.10", 22, TCP, StatusAllowed)
	checkRuleIPPort(t, rules, "10.0.0.5", 443, TCP, StatusDenied)
}

func checkRuleIPPort(t *testing.T, rules []Rule, ip string, port uint16, proto Protocol, status Status) {
	t.Helper()
	parsed := netip.MustParseAddr(ip)
	for _, r := range rules {
		if r.Kind == RuleKindIPPort && r.IP == parsed && r.Port == port && r.Protocol == proto {
			if r.Status != status {
				t.Fatalf("IP %s port %d/%s: expected %v, got %v", ip, port, proto, status, r.Status)
			}
			return
		}
	}
	t.Fatalf("IP %s port %d/%s not found", ip, port, proto)
}

func TestParseCIDRRules(t *testing.T) {
	raw := `[ 1] Anywhere                   DENY IN     10.0.0.0/8
[ 2] 192.168.1.0/24             DENY OUT    Anywhere
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	checkRuleCIDR(t, rules, "10.0.0.0/8", StatusDenied, RuleKindIPRange, From)
	checkRuleCIDR(t, rules, "192.168.1.0/24", StatusDenied, RuleKindIPRange, To)
}

func checkRuleCIDR(t *testing.T, rules []Rule, cidr string, status Status, kind RuleKind, dir Direction) {
	t.Helper()
	parsed := netip.MustParsePrefix(cidr)
	for _, r := range rules {
		if r.Kind == kind && r.Prefix == parsed && r.Direction == dir {
			if r.Status != status {
				t.Fatalf("CIDR %s: expected %v, got %v", cidr, status, r.Status)
			}
			return
		}
	}
	t.Fatalf("CIDR %s not found", cidr)
}

func TestParseRulesWithDuplicates(t *testing.T) {
	raw := `[ 1] 22/tcp  ALLOW IN  Anywhere
[ 2] 22/tcp  ALLOW IN  Anywhere
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 duplicates, got %d", len(rules))
	}
}

func TestParseRulesMalformed(t *testing.T) {
	raw := `[ 1] Not a real rule
[ 2] 22/tcp                     ALLOW IN    Anywhere
random garbage
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 parseable rule, got %d", len(rules))
	}
	if rules[0].Port != 22 || rules[0].Protocol != TCP || rules[0].Status != StatusAllowed {
		t.Fatal("expected 22/tcp allowed")
	}
}

func TestParseRulesWithComment(t *testing.T) {
	raw := `[ 1] 22/tcp                     ALLOW IN    Anywhere                   # SSH
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Comment != "SSH" {
		t.Errorf("expected comment 'SSH', got %q", rules[0].Comment)
	}
}

func TestParseALLOWOUT(t *testing.T) {
	raw := `[ 1] 192.168.1.10               ALLOW OUT   Anywhere
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Kind != RuleKindIP {
		t.Fatal("expected IP kind")
	}
	if rules[0].Direction != To {
		t.Fatal("expected To direction for ALLOW OUT")
	}
	if rules[0].Status != StatusAllowed {
		t.Fatal("expected Allowed status")
	}
}

func TestParseDENYOUT(t *testing.T) {
	raw := `[ 1] 10.0.0.5                  DENY OUT    Anywhere
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Kind != RuleKindIP {
		t.Fatal("expected IP kind")
	}
	if rules[0].Direction != To {
		t.Fatal("expected To direction for DENY OUT")
	}
	if rules[0].Status != StatusDenied {
		t.Fatal("expected Denied status")
	}
}

func TestParseIsEnabledInvalid(t *testing.T) {
	_, err := parseIsEnabled("Status: unknown\n")
	if err == nil {
		t.Fatal("expected error for unknown status")
	}
}

func TestParseTargetWithIPAndPortProto(t *testing.T) {
	raw := `[ 1] 172.17.0.1 53/udp          ALLOW IN    172.16.0.0/12              # allow-docker-dns
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Kind != RuleKindIPPort {
		t.Fatalf("expected IPPort kind, got %s", rules[0].Kind)
	}
	if rules[0].Port != 53 {
		t.Fatalf("expected port 53, got %d", rules[0].Port)
	}
	if rules[0].Protocol != UDP {
		t.Fatalf("expected UDP, got %s", rules[0].Protocol)
	}
	if rules[0].IP.String() != "172.17.0.1" {
		t.Fatalf("expected IP 172.17.0.1, got %s", rules[0].IP)
	}
	if rules[0].Direction != From {
		t.Fatalf("expected From direction, got %s", rules[0].Direction)
	}
	if rules[0].Comment != "allow-docker-dns" {
		t.Fatalf("expected comment 'allow-docker-dns', got %q", rules[0].Comment)
	}
}

func TestParseTargetWithIPAndPortProtoV6(t *testing.T) {
	raw := `[ 1] 2001:db8::1 53/udp (v6)    ALLOW IN    Anywhere (v6)
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Kind != RuleKindIPPort {
		t.Fatalf("expected IPPort kind, got %s", rules[0].Kind)
	}
	if rules[0].Port != 53 {
		t.Fatalf("expected port 53, got %d", rules[0].Port)
	}
	if rules[0].Protocol != UDP {
		t.Fatalf("expected UDP, got %s", rules[0].Protocol)
	}
}

func TestParseRulesWithCommentAndV6(t *testing.T) {
	raw := `[ 1] 22/tcp (v6)                ALLOW IN    Anywhere (v6)             # SSH IPv6
`
	rules, err := parseRules(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Comment != "SSH IPv6" {
		t.Errorf("expected comment 'SSH IPv6', got %q", rules[0].Comment)
	}
	if rules[0].Protocol != TCP {
		t.Fatal("expected TCP protocol")
	}
	if rules[0].Port != 22 {
		t.Fatal("expected port 22")
	}
}
