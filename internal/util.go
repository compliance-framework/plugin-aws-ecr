package internal

import "strings"

func StringAddressed(str string) *string {
	return &str
}

// FilterByAccounts returns only the repositories whose AccountID appears in
// accounts.  If accounts is empty the full list is returned unchanged.
func FilterByAccounts(repos []RepositoryContext, accounts []string) []RepositoryContext {
	if len(accounts) == 0 {
		return repos
	}
	allowed := make(map[string]struct{}, len(accounts))
	for _, a := range accounts {
		allowed[a] = struct{}{}
	}
	out := repos[:0]
	for _, r := range repos {
		if _, ok := allowed[r.AccountID]; ok {
			out = append(out, r)
		}
	}
	return out
}

// arnPartition returns the AWS partition for the given region.
// cn-* regions use aws-cn; us-gov-* regions use aws-us-gov; everything else uses aws.
func arnPartition(region string) string {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	default:
		return "aws"
	}
}

func MergeMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, values := range maps {
		for k, v := range values {
			result[k] = v
		}
	}
	return result
}
