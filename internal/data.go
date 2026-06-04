package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/hashicorp/go-hclog"
)

// ECRClient is the subset of the AWS ECR API used by DataFetcher.
type ECRClient interface {
	DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
	GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
	ListTagsForResource(ctx context.Context, params *ecr.ListTagsForResourceInput, optFns ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
	GetRegistryScanningConfiguration(ctx context.Context, params *ecr.GetRegistryScanningConfigurationInput, optFns ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error)
	DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

// RepositoryContext holds all fields required by CONFIG ECR compliance policies.
type RepositoryContext struct {
	ResourceType         string            `json:"resource_type"`
	RepositoryArn        string            `json:"repository_arn"`
	RepositoryName       string            `json:"repository_name"`
	RegistryID           string            `json:"registry_id"`
	Region               string            `json:"region"`
	AccountID            string            `json:"account_id"`
	ImageTagImmutability string            `json:"image_tag_immutability"`
	ScanOnPush           bool              `json:"scan_on_push"`
	EncryptionType       string            `json:"encryption_type"`
	KmsKey               string            `json:"kms_key"`
	HasLifecyclePolicy   bool              `json:"has_lifecycle_policy"`
	LifecyclePolicyText  string            `json:"lifecycle_policy_text"`
	HasRepositoryPolicy  bool              `json:"has_repository_policy"`
	RepositoryPolicyText string            `json:"repository_policy_text"`
	Tags                 map[string]string `json:"tags"`
}

// RegistryContext holds account-level scanning configuration for CONFIG policies.
type RegistryContext struct {
	ResourceType            string `json:"resource_type"`
	RegistryID              string `json:"registry_id"`
	Region                  string `json:"region"`
	AccountID               string `json:"account_id"`
	RegistryScanType        string `json:"registry_scan_type"`
	EnhancedScanningEnabled bool   `json:"enhanced_scanning_enabled"`
}

// ImageContext holds image-level scan data for DYNAMIC (90-day lookback) policies.
type ImageContext struct {
	ResourceType     string    `json:"resource_type"`
	RepositoryArn    string    `json:"repository_arn"`
	RepositoryName   string    `json:"repository_name"`
	Region           string    `json:"region"`
	AccountID        string    `json:"account_id"`
	ImageDigest      string    `json:"image_digest"`
	ImageTags        []string  `json:"image_tags"`
	ImagePushedAt    time.Time `json:"image_pushed_at"`
	ScanStatus       string    `json:"scan_status"`
	FindingsCritical int       `json:"findings_critical"`
	FindingsHigh     int       `json:"findings_high"`
	HasSeverityData  bool      `json:"has_severity_data"`
}

// ToOPAInput serialises c to a map[string]interface{} suitable for OPA input.
func (c RepositoryContext) ToOPAInput() (map[string]interface{}, error) {
	return toMap(c)
}

// ToOPAInput serialises c to a map[string]interface{} suitable for OPA input.
func (c RegistryContext) ToOPAInput() (map[string]interface{}, error) {
	return toMap(c)
}

// ToOPAInput serialises c to a map[string]interface{} suitable for OPA input.
func (c ImageContext) ToOPAInput() (map[string]interface{}, error) {
	return toMap(c)
}

func toMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// DataFetcher retrieves ECR data across configured regions.
type DataFetcher struct {
	logger    hclog.Logger
	config    *PluginConfig
	newClient func(ctx context.Context, region string) (ECRClient, error)
}

// NewDataFetcher returns a DataFetcher using the standard AWS credential chain.
func NewDataFetcher(logger hclog.Logger, cfg *PluginConfig) *DataFetcher {
	return &DataFetcher{
		logger: logger,
		config: cfg,
		newClient: func(ctx context.Context, region string) (ECRClient, error) {
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return ecr.NewFromConfig(awsCfg), nil
		},
	}
}

// FetchRepositories returns all private ECR repositories in the given region.
func (df *DataFetcher) FetchRepositories(ctx context.Context, region string) ([]RepositoryContext, error) {
	client, err := df.newClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("create ECR client: %w", err)
	}

	var repos []RepositoryContext
	var nextToken *string
	for {
		out, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("DescribeRepositories: %w", err)
		}
		for _, r := range out.Repositories {
			repo, err := df.buildRepositoryContext(ctx, client, region, r)
			if err != nil {
				return nil, fmt.Errorf("repository %s: %w", aws.ToString(r.RepositoryName), err)
			}
			repos = append(repos, repo)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return repos, nil
}

func (df *DataFetcher) buildRepositoryContext(ctx context.Context, client ECRClient, region string, r types.Repository) (RepositoryContext, error) {
	repoName := aws.ToString(r.RepositoryName)
	repoARN := aws.ToString(r.RepositoryArn)

	hasLifecycle, lifecycleText, err := df.fetchLifecyclePolicy(ctx, client, repoName)
	if err != nil {
		return RepositoryContext{}, fmt.Errorf("GetLifecyclePolicy: %w", err)
	}

	hasRepoPolicy, repoPolicyText, err := df.fetchRepositoryPolicy(ctx, client, repoName)
	if err != nil {
		return RepositoryContext{}, fmt.Errorf("GetRepositoryPolicy: %w", err)
	}

	tagsOut, err := client.ListTagsForResource(ctx, &ecr.ListTagsForResourceInput{
		ResourceArn: r.RepositoryArn,
	})
	if err != nil {
		return RepositoryContext{}, fmt.Errorf("ListTagsForResource: %w", err)
	}
	tags := make(map[string]string, len(tagsOut.Tags))
	for _, t := range tagsOut.Tags {
		tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
	}

	encType := ""
	kmsKey := ""
	if r.EncryptionConfiguration != nil {
		encType = string(r.EncryptionConfiguration.EncryptionType)
		kmsKey = aws.ToString(r.EncryptionConfiguration.KmsKey)
	}

	scanOnPush := false
	if r.ImageScanningConfiguration != nil {
		scanOnPush = r.ImageScanningConfiguration.ScanOnPush
	}

	return RepositoryContext{
		ResourceType:         "ecr-repository",
		RepositoryArn:        repoARN,
		RepositoryName:       repoName,
		RegistryID:           aws.ToString(r.RegistryId),
		Region:               region,
		AccountID:            arnAccountID(repoARN),
		ImageTagImmutability: string(r.ImageTagMutability),
		ScanOnPush:           scanOnPush,
		EncryptionType:       encType,
		KmsKey:               kmsKey,
		HasLifecyclePolicy:   hasLifecycle,
		LifecyclePolicyText:  lifecycleText,
		HasRepositoryPolicy:  hasRepoPolicy,
		RepositoryPolicyText: repoPolicyText,
		Tags:                 tags,
	}, nil
}

func (df *DataFetcher) fetchLifecyclePolicy(ctx context.Context, client ECRClient, repoName string) (bool, string, error) {
	out, err := client.GetLifecyclePolicy(ctx, &ecr.GetLifecyclePolicyInput{
		RepositoryName: aws.String(repoName),
	})
	if err != nil {
		var nfe *types.LifecyclePolicyNotFoundException
		if errors.As(err, &nfe) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, aws.ToString(out.LifecyclePolicyText), nil
}

func (df *DataFetcher) fetchRepositoryPolicy(ctx context.Context, client ECRClient, repoName string) (bool, string, error) {
	out, err := client.GetRepositoryPolicy(ctx, &ecr.GetRepositoryPolicyInput{
		RepositoryName: aws.String(repoName),
	})
	if err != nil {
		var nfe *types.RepositoryPolicyNotFoundException
		if errors.As(err, &nfe) {
			return false, "", nil
		}
		return false, "", err
	}
	return true, aws.ToString(out.PolicyText), nil
}

// FetchRegistryConfig returns the account-level scanning configuration for the given region.
func (df *DataFetcher) FetchRegistryConfig(ctx context.Context, region string) (RegistryContext, error) {
	client, err := df.newClient(ctx, region)
	if err != nil {
		return RegistryContext{}, fmt.Errorf("create ECR client: %w", err)
	}

	out, err := client.GetRegistryScanningConfiguration(ctx, &ecr.GetRegistryScanningConfigurationInput{})
	if err != nil {
		return RegistryContext{}, fmt.Errorf("GetRegistryScanningConfiguration: %w", err)
	}

	scanType := string(out.ScanningConfiguration.ScanType)
	enhanced := scanType == "ENHANCED"

	return RegistryContext{
		ResourceType:            "ecr-registry",
		RegistryID:              aws.ToString(out.RegistryId),
		Region:                  region,
		AccountID:               aws.ToString(out.RegistryId),
		RegistryScanType:        scanType,
		EnhancedScanningEnabled: enhanced,
	}, nil
}

// FetchImages returns ImageContext records for all images pushed within lookbackDays across the given repositories.
func (df *DataFetcher) FetchImages(ctx context.Context, region string, repoNames []string, accountID string, lookbackDays int) ([]ImageContext, error) {
	client, err := df.newClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("create ECR client: %w", err)
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -lookbackDays)
	var images []ImageContext

	for _, repoName := range repoNames {
		repoARN := fmt.Sprintf("arn:%s:ecr:%s:%s:repository/%s", arnPartition(region), region, accountID, repoName)
		repoImages, err := df.fetchImagesForRepo(ctx, client, region, repoName, repoARN, cutoff)
		if err != nil {
			df.logger.Warn("failed to fetch images for repository", "repository", repoName, "error", err)
			continue
		}
		images = append(images, repoImages...)
	}
	return images, nil
}

func (df *DataFetcher) fetchImagesForRepo(ctx context.Context, client ECRClient, region, repoName, repoARN string, cutoff time.Time) ([]ImageContext, error) {
	var images []ImageContext
	var nextToken *string

	for {
		out, err := client.DescribeImages(ctx, &ecr.DescribeImagesInput{
			RepositoryName: aws.String(repoName),
			NextToken:      nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("DescribeImages: %w", err)
		}

		for _, detail := range out.ImageDetails {
			if detail.ImagePushedAt == nil || detail.ImagePushedAt.Before(cutoff) {
				continue
			}
			digest := aws.ToString(detail.ImageDigest)
			if digest == "" {
				continue
			}

			imgCtx := df.fetchImageScanContext(ctx, client, region, repoName, repoARN, detail)
			images = append(images, imgCtx)
		}

		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return images, nil
}

func (df *DataFetcher) fetchImageScanContext(ctx context.Context, client ECRClient, region, repoName, repoARN string, detail types.ImageDetail) ImageContext {
	digest := aws.ToString(detail.ImageDigest)
	pushedAt := time.Time{}
	if detail.ImagePushedAt != nil {
		pushedAt = *detail.ImagePushedAt
	}

	tags := detail.ImageTags
	if tags == nil {
		tags = []string{}
	}

	imgCtx := ImageContext{
		ResourceType:   "ecr-image",
		RepositoryArn:  repoARN,
		RepositoryName: repoName,
		Region:         region,
		AccountID:      arnAccountID(repoARN),
		ImageDigest:    digest,
		ImageTags:      tags,
		ImagePushedAt:  pushedAt,
		ScanStatus:     "UNSUPPORTED",
		FindingsCritical: 0,
		FindingsHigh:     0,
		HasSeverityData:  false,
	}

	findingsOut, err := client.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
		RepositoryName: aws.String(repoName),
		ImageId:        &types.ImageIdentifier{ImageDigest: aws.String(digest)},
	})
	if err != nil {
		var snfe *types.ScanNotFoundException
		if !errors.As(err, &snfe) {
			df.logger.Warn("failed to get scan findings", "repository", repoName, "digest", digest, "error", err)
		}
		return imgCtx
	}

	if findingsOut.ImageScanStatus != nil {
		imgCtx.ScanStatus = string(findingsOut.ImageScanStatus.Status)
	}

	if findingsOut.ImageScanFindings != nil && imgCtx.ScanStatus == "COMPLETE" {
		counts := findingsOut.ImageScanFindings.FindingSeverityCounts
		if counts != nil {
			imgCtx.FindingsCritical = int(counts["CRITICAL"])
			imgCtx.FindingsHigh = int(counts["HIGH"])
			imgCtx.HasSeverityData = true
		}
	}

	return imgCtx
}

// arnAccountID extracts the 12-digit account ID from an ECR ARN.
// ARN format: arn:aws:ecr:<region>:<account-id>:repository/<name>
func arnAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
