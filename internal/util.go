package internal

import "strings"

func StringAddressed(str string) *string {
	return &str
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
