package internal

import (
	"testing"
)

func TestParseConfig_RequiresRegions(t *testing.T) {
	_, err := ParseConfig(map[string]string{})
	if err == nil {
		t.Fatal("expected error when regions is missing, got nil")
	}
}

func TestParseConfig_SingleRegion(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{"regions": "us-east-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Regions) != 1 || cfg.Regions[0] != "us-east-1" {
		t.Fatalf("expected [us-east-1], got %v", cfg.Regions)
	}
}

func TestParseConfig_MultipleRegions(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{"regions": "us-east-1, eu-west-1 , ap-southeast-2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"us-east-1", "eu-west-1", "ap-southeast-2"}
	if len(cfg.Regions) != len(want) {
		t.Fatalf("expected %v, got %v", want, cfg.Regions)
	}
	for i, r := range want {
		if cfg.Regions[i] != r {
			t.Errorf("region[%d]: want %q, got %q", i, r, cfg.Regions[i])
		}
	}
}

func TestParseConfig_MultipleAccounts(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{
		"regions":  "us-east-1",
		"accounts": "111111111111, 222222222222",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"111111111111", "222222222222"}
	if got, wantLen := len(cfg.Accounts), len(want); got != wantLen {
		t.Fatalf("accounts: want %d entries, got %d", wantLen, got)
	}
	for i, a := range want {
		if cfg.Accounts[i] != a {
			t.Errorf("account[%d]: want %q, got %q", i, a, cfg.Accounts[i])
		}
	}
}

func TestParseConfig_PolicyLabels(t *testing.T) {
	cfg, err := ParseConfig(map[string]string{
		"regions":       "us-east-1",
		"policy_labels": `{"env":"prod"}`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PolicyLabels["env"] != "prod" {
		t.Errorf("expected policy_labels env=prod, got %v", cfg.PolicyLabels)
	}
}

func TestParseConfig_InvalidPolicyLabels(t *testing.T) {
	_, err := ParseConfig(map[string]string{
		"regions":       "us-east-1",
		"policy_labels": `not-json`,
	})
	if err == nil {
		t.Fatal("expected error for invalid policy_labels JSON, got nil")
	}
}

func TestEvalLabelsStable(t *testing.T) {
	repoLabels := repositoryBaseLabels()
	if repoLabels["provider"] != "aws" || repoLabels["type"] != "ecr-repository" {
		t.Errorf("repository base labels changed: %v", repoLabels)
	}
	if len(repoLabels) != 2 {
		t.Errorf("unexpected extra labels: %v", repoLabels)
	}

	regLabels := registryBaseLabels()
	if regLabels["provider"] != "aws" || regLabels["type"] != "ecr-registry" {
		t.Errorf("registry base labels changed: %v", regLabels)
	}

	imgLabels := imageBaseLabels()
	if imgLabels["provider"] != "aws" || imgLabels["type"] != "ecr-image" {
		t.Errorf("image base labels changed: %v", imgLabels)
	}
}
