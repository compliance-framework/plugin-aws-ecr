package internal

import (
	"testing"
)

func copyRepos(src []RepositoryContext) []RepositoryContext {
	dst := make([]RepositoryContext, len(src))
	copy(dst, src)
	return dst
}

func assertReposUnchanged(t *testing.T, original, after []RepositoryContext) {
	t.Helper()
	if len(after) != len(original) {
		t.Errorf("input slice length changed: want %d, got %d", len(original), len(after))
		return
	}
	for i := range original {
		if original[i].AccountID != after[i].AccountID || original[i].RepositoryName != after[i].RepositoryName {
			t.Errorf("input slice mutated at index %d: want %+v, got %+v", i, original[i], after[i])
		}
	}
}

func TestFilterByAccounts(t *testing.T) {
	seed := []RepositoryContext{
		{AccountID: "111111111111", RepositoryName: "repo-a"},
		{AccountID: "222222222222", RepositoryName: "repo-b"},
		{AccountID: "333333333333", RepositoryName: "repo-c"},
	}

	t.Run("empty accounts returns all", func(t *testing.T) {
		repos := copyRepos(seed)
		got := FilterByAccounts(repos, nil)
		if len(got) != 3 {
			t.Fatalf("want 3, got %d", len(got))
		}
		assertReposUnchanged(t, seed, repos)
	})

	t.Run("filters to matching accounts", func(t *testing.T) {
		repos := copyRepos(seed)
		got := FilterByAccounts(repos, []string{"111111111111", "333333333333"})
		if len(got) != 2 {
			t.Fatalf("want 2, got %d", len(got))
		}
		if got[0].AccountID != "111111111111" || got[1].AccountID != "333333333333" {
			t.Errorf("unexpected accounts: %v", got)
		}
		assertReposUnchanged(t, seed, repos)
	})

	t.Run("no match returns empty", func(t *testing.T) {
		repos := copyRepos(seed)
		got := FilterByAccounts(repos, []string{"999999999999"})
		if len(got) != 0 {
			t.Fatalf("want 0, got %d", len(got))
		}
		assertReposUnchanged(t, seed, repos)
	})
}

func TestArnPartition(t *testing.T) {
	cases := []struct {
		region string
		want   string
	}{
		{"us-east-1", "aws"},
		{"eu-west-2", "aws"},
		{"ap-southeast-1", "aws"},
		{"cn-north-1", "aws-cn"},
		{"cn-northwest-1", "aws-cn"},
		{"us-gov-west-1", "aws-us-gov"},
		{"us-gov-east-1", "aws-us-gov"},
	}
	for _, tc := range cases {
		if got := arnPartition(tc.region); got != tc.want {
			t.Errorf("arnPartition(%q) = %q, want %q", tc.region, got, tc.want)
		}
	}
}

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
