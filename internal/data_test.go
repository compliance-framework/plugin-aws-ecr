package internal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/hashicorp/go-hclog"
)

// mockECRClient implements ECRClient for testing.
type mockECRClient struct {
	describeRepositories          func(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	getLifecyclePolicy            func(context.Context, *ecr.GetLifecyclePolicyInput, ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error)
	getRepositoryPolicy           func(context.Context, *ecr.GetRepositoryPolicyInput, ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error)
	listTagsForResource           func(context.Context, *ecr.ListTagsForResourceInput, ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error)
	getRegistryScanningConfig     func(context.Context, *ecr.GetRegistryScanningConfigurationInput, ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error)
	describeImages                func(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	describeImageScanFindings     func(context.Context, *ecr.DescribeImageScanFindingsInput, ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
}

func (m *mockECRClient) DescribeRepositories(ctx context.Context, params *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	return m.describeRepositories(ctx, params, optFns...)
}
func (m *mockECRClient) GetLifecyclePolicy(ctx context.Context, params *ecr.GetLifecyclePolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
	return m.getLifecyclePolicy(ctx, params, optFns...)
}
func (m *mockECRClient) GetRepositoryPolicy(ctx context.Context, params *ecr.GetRepositoryPolicyInput, optFns ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
	return m.getRepositoryPolicy(ctx, params, optFns...)
}
func (m *mockECRClient) ListTagsForResource(ctx context.Context, params *ecr.ListTagsForResourceInput, optFns ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
	return m.listTagsForResource(ctx, params, optFns...)
}
func (m *mockECRClient) GetRegistryScanningConfiguration(ctx context.Context, params *ecr.GetRegistryScanningConfigurationInput, optFns ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error) {
	return m.getRegistryScanningConfig(ctx, params, optFns...)
}
func (m *mockECRClient) DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	return m.describeImages(ctx, params, optFns...)
}
func (m *mockECRClient) DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	return m.describeImageScanFindings(ctx, params, optFns...)
}

func newTestFetcher(client ECRClient) *DataFetcher {
	return &DataFetcher{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{Regions: []string{"us-east-1"}},
		newClient: func(_ context.Context, _ string) (ECRClient, error) {
			return client, nil
		},
	}
}

func noopPerRepoMock() *mockECRClient {
	return &mockECRClient{
		getLifecyclePolicy: func(_ context.Context, _ *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
			return nil, &types.LifecyclePolicyNotFoundException{}
		},
		getRepositoryPolicy: func(_ context.Context, _ *ecr.GetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
			return nil, &types.RepositoryPolicyNotFoundException{}
		},
		listTagsForResource: func(_ context.Context, _ *ecr.ListTagsForResourceInput, _ ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
			return &ecr.ListTagsForResourceOutput{}, nil
		},
	}
}

func TestFetchRepositories_Empty(t *testing.T) {
	mock := noopPerRepoMock()
	mock.describeRepositories = func(_ context.Context, _ *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
		return &ecr.DescribeRepositoriesOutput{}, nil
	}
	f := newTestFetcher(mock)
	repos, err := f.FetchRepositories(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repos) != 0 {
		t.Errorf("expected 0 repos, got %d", len(repos))
	}
}

func TestFetchRepositories_SingleRepo(t *testing.T) {
	arn := "arn:aws:ecr:us-east-1:123456789012:repository/my-app"
	mock := noopPerRepoMock()
	mock.describeRepositories = func(_ context.Context, _ *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
		return &ecr.DescribeRepositoriesOutput{
			Repositories: []types.Repository{
				{
					RepositoryArn:        aws.String(arn),
					RepositoryName:       aws.String("my-app"),
					RegistryId:           aws.String("123456789012"),
					ImageTagMutability: types.ImageTagMutabilityImmutable,
					ImageScanningConfiguration: &types.ImageScanningConfiguration{
						ScanOnPush: true,
					},
					EncryptionConfiguration: &types.EncryptionConfiguration{
						EncryptionType: types.EncryptionTypeKms,
						KmsKey:         aws.String("arn:aws:kms:us-east-1:123456789012:key/abc"),
					},
				},
			},
		}, nil
	}
	mock.listTagsForResource = func(_ context.Context, _ *ecr.ListTagsForResourceInput, _ ...func(*ecr.Options)) (*ecr.ListTagsForResourceOutput, error) {
		return &ecr.ListTagsForResourceOutput{
			Tags: []types.Tag{
				{Key: aws.String("Environment"), Value: aws.String("prod")},
			},
		}, nil
	}

	f := newTestFetcher(mock)
	repos, err := f.FetchRepositories(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected 1 repo, got %d", len(repos))
	}
	r := repos[0]
	if r.ResourceType != "ecr-repository" {
		t.Errorf("resource_type: want ecr-repository, got %q", r.ResourceType)
	}
	if r.RepositoryArn != arn {
		t.Errorf("arn: want %q, got %q", arn, r.RepositoryArn)
	}
	if r.AccountID != "123456789012" {
		t.Errorf("account_id: want 123456789012, got %q", r.AccountID)
	}
	if !r.ScanOnPush {
		t.Error("scan_on_push: want true, got false")
	}
	if r.ImageTagImmutability != "IMMUTABLE" {
		t.Errorf("image_tag_immutability: want IMMUTABLE, got %q", r.ImageTagImmutability)
	}
	if r.EncryptionType != "KMS" {
		t.Errorf("encryption_type: want KMS, got %q", r.EncryptionType)
	}
	if r.HasLifecyclePolicy {
		t.Error("has_lifecycle_policy: want false for not-found")
	}
	if r.HasRepositoryPolicy {
		t.Error("has_repository_policy: want false for not-found")
	}
	if r.Tags["Environment"] != "prod" {
		t.Errorf("tags: expected Environment=prod, got %v", r.Tags)
	}
}

func TestFetchRepositories_WithLifecycleAndPolicy(t *testing.T) {
	arn := "arn:aws:ecr:us-east-1:123456789012:repository/prod-app"
	mock := noopPerRepoMock()
	mock.describeRepositories = func(_ context.Context, _ *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
		return &ecr.DescribeRepositoriesOutput{
			Repositories: []types.Repository{
				{
					RepositoryArn:  aws.String(arn),
					RepositoryName: aws.String("prod-app"),
					RegistryId:     aws.String("123456789012"),
					ImageScanningConfiguration: &types.ImageScanningConfiguration{ScanOnPush: false},
					EncryptionConfiguration:    &types.EncryptionConfiguration{EncryptionType: types.EncryptionTypeAes256},
				},
			},
		}, nil
	}
	mock.getLifecyclePolicy = func(_ context.Context, _ *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
		return &ecr.GetLifecyclePolicyOutput{
			LifecyclePolicyText: aws.String(`{"rules":[]}`),
		}, nil
	}
	mock.getRepositoryPolicy = func(_ context.Context, _ *ecr.GetRepositoryPolicyInput, _ ...func(*ecr.Options)) (*ecr.GetRepositoryPolicyOutput, error) {
		return &ecr.GetRepositoryPolicyOutput{
			PolicyText: aws.String(`{"Version":"2012-10-17","Statement":[]}`),
		}, nil
	}

	f := newTestFetcher(mock)
	repos, err := f.FetchRepositories(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r := repos[0]
	if !r.HasLifecyclePolicy {
		t.Error("has_lifecycle_policy: want true")
	}
	if r.LifecyclePolicyText == "" {
		t.Error("lifecycle_policy_text: want non-empty")
	}
	if !r.HasRepositoryPolicy {
		t.Error("has_repository_policy: want true")
	}
	if r.EncryptionType != "AES256" {
		t.Errorf("encryption_type: want AES256, got %q", r.EncryptionType)
	}
}

func TestFetchRepositories_Pagination(t *testing.T) {
	callCount := 0
	mock := noopPerRepoMock()
	mock.describeRepositories = func(_ context.Context, params *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
		callCount++
		if callCount == 1 {
			return &ecr.DescribeRepositoriesOutput{
				Repositories: []types.Repository{{
					RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/repo-a"),
					RepositoryName: aws.String("repo-a"),
					RegistryId:     aws.String("123456789012"),
				}},
				NextToken: aws.String("page2"),
			}, nil
		}
		return &ecr.DescribeRepositoriesOutput{
			Repositories: []types.Repository{{
				RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/repo-b"),
				RepositoryName: aws.String("repo-b"),
				RegistryId:     aws.String("123456789012"),
			}},
		}, nil
	}

	f := newTestFetcher(mock)
	repos, err := f.FetchRepositories(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(repos) != 2 {
		t.Errorf("expected 2 repos, got %d", len(repos))
	}
	if callCount != 2 {
		t.Errorf("expected 2 DescribeRepositories calls, got %d", callCount)
	}
}

func TestFetchRegistryConfig_Enhanced(t *testing.T) {
	mock := noopPerRepoMock()
	mock.getRegistryScanningConfig = func(_ context.Context, _ *ecr.GetRegistryScanningConfigurationInput, _ ...func(*ecr.Options)) (*ecr.GetRegistryScanningConfigurationOutput, error) {
		return &ecr.GetRegistryScanningConfigurationOutput{
			RegistryId: aws.String("123456789012"),
			ScanningConfiguration: &types.RegistryScanningConfiguration{
				ScanType: types.ScanTypeEnhanced,
			},
		}, nil
	}

	f := newTestFetcher(mock)
	reg, err := f.FetchRegistryConfig(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg.ResourceType != "ecr-registry" {
		t.Errorf("resource_type: want ecr-registry, got %q", reg.ResourceType)
	}
	if reg.RegistryScanType != "ENHANCED" {
		t.Errorf("registry_scan_type: want ENHANCED, got %q", reg.RegistryScanType)
	}
	if !reg.EnhancedScanningEnabled {
		t.Error("enhanced_scanning_enabled: want true")
	}
}

func TestFetchImages_WithinLookback(t *testing.T) {
	now := time.Now().UTC()
	recentDigest := "sha256:aaaa"
	oldDigest := "sha256:bbbb"

	mock := noopPerRepoMock()
	mock.describeImages = func(_ context.Context, params *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
		recentTime := now.Add(-10 * 24 * time.Hour)  // 10 days ago — in window
		oldTime := now.Add(-100 * 24 * time.Hour)     // 100 days ago — outside window
		return &ecr.DescribeImagesOutput{
			ImageDetails: []types.ImageDetail{
				{ImageDigest: aws.String(recentDigest), ImagePushedAt: &recentTime, ImageTags: []string{"latest"}},
				{ImageDigest: aws.String(oldDigest), ImagePushedAt: &oldTime},
			},
		}, nil
	}
	mock.describeImageScanFindings = func(_ context.Context, params *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
		scanTime := now.Add(-9 * 24 * time.Hour)
		return &ecr.DescribeImageScanFindingsOutput{
			ImageScanStatus: &types.ImageScanStatus{Status: types.ScanStatusComplete},
			ImageScanFindings: &types.ImageScanFindings{
				ImageScanCompletedAt:  &scanTime,
				FindingSeverityCounts: map[string]int32{"CRITICAL": 0, "HIGH": 2},
			},
		}, nil
	}

	f := newTestFetcher(mock)
	images, err := f.FetchImages(context.Background(), "us-east-1", []string{"my-repo"}, "123456789012", 90)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image (old one filtered), got %d", len(images))
	}
	img := images[0]
	if img.ImageDigest != recentDigest {
		t.Errorf("digest: want %q, got %q", recentDigest, img.ImageDigest)
	}
	if img.ScanStatus != "COMPLETE" {
		t.Errorf("scan_status: want COMPLETE, got %q", img.ScanStatus)
	}
	if img.FindingsHigh != 2 {
		t.Errorf("findings_high: want 2, got %d", img.FindingsHigh)
	}
	if !img.HasSeverityData {
		t.Error("has_severity_data: want true")
	}
}

func TestFetchImages_NoScan(t *testing.T) {
	now := time.Now().UTC()
	pushedAt := now.Add(-5 * 24 * time.Hour)

	mock := noopPerRepoMock()
	mock.describeImages = func(_ context.Context, _ *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
		return &ecr.DescribeImagesOutput{
			ImageDetails: []types.ImageDetail{
				{ImageDigest: aws.String("sha256:cccc"), ImagePushedAt: &pushedAt},
			},
		}, nil
	}
	mock.describeImageScanFindings = func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
		return nil, &types.ScanNotFoundException{}
	}

	f := newTestFetcher(mock)
	images, err := f.FetchImages(context.Background(), "us-east-1", []string{"my-repo"}, "123456789012", 90)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(images))
	}
	img := images[0]
	if img.ScanStatus != "UNSUPPORTED" {
		t.Errorf("scan_status: want UNSUPPORTED for no scan, got %q", img.ScanStatus)
	}
	if img.HasSeverityData {
		t.Error("has_severity_data: want false when no scan")
	}
}

func TestFetchImages_Pagination(t *testing.T) {
	now := time.Now().UTC()
	pushedAt := now.Add(-1 * 24 * time.Hour)
	callCount := 0

	mock := noopPerRepoMock()
	mock.describeImages = func(_ context.Context, params *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
		callCount++
		if callCount == 1 {
			return &ecr.DescribeImagesOutput{
				ImageDetails: []types.ImageDetail{{ImageDigest: aws.String("sha256:page1"), ImagePushedAt: &pushedAt}},
				NextToken:    aws.String("tok"),
			}, nil
		}
		return &ecr.DescribeImagesOutput{
			ImageDetails: []types.ImageDetail{{ImageDigest: aws.String("sha256:page2"), ImagePushedAt: &pushedAt}},
		}, nil
	}
	mock.describeImageScanFindings = func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
		return nil, &types.ScanNotFoundException{}
	}

	f := newTestFetcher(mock)
	images, err := f.FetchImages(context.Background(), "us-east-1", []string{"my-repo"}, "123456789012", 90)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(images) != 2 {
		t.Errorf("expected 2 images, got %d", len(images))
	}
	if callCount != 2 {
		t.Errorf("expected 2 DescribeImages calls, got %d", callCount)
	}
}

func TestArnAccountID(t *testing.T) {
	cases := []struct {
		arn  string
		want string
	}{
		{"arn:aws:ecr:us-east-1:123456789012:repository/foo", "123456789012"},
		{"arn:aws:ecr:eu-west-1:999999999999:repository/bar", "999999999999"},
		{"invalid", ""},
	}
	for _, tc := range cases {
		got := arnAccountID(tc.arn)
		if got != tc.want {
			t.Errorf("arnAccountID(%q): want %q, got %q", tc.arn, tc.want, got)
		}
	}
}

func TestRepositoryContext_LifecyclePolicyNotFound(t *testing.T) {
	mock := noopPerRepoMock()
	mock.describeRepositories = func(_ context.Context, _ *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
		return &ecr.DescribeRepositoriesOutput{
			Repositories: []types.Repository{{
				RepositoryArn:  aws.String("arn:aws:ecr:us-east-1:123456789012:repository/no-policy"),
				RepositoryName: aws.String("no-policy"),
				RegistryId:     aws.String("123456789012"),
			}},
		}, nil
	}
	mock.getLifecyclePolicy = func(_ context.Context, _ *ecr.GetLifecyclePolicyInput, _ ...func(*ecr.Options)) (*ecr.GetLifecyclePolicyOutput, error) {
		return nil, &types.LifecyclePolicyNotFoundException{Message: aws.String("not found")}
	}

	f := newTestFetcher(mock)
	repos, err := f.FetchRepositories(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if repos[0].HasLifecyclePolicy {
		t.Error("has_lifecycle_policy: want false when LifecyclePolicyNotFoundException")
	}
}

func TestRepositoryContext_ToOPAInput(t *testing.T) {
	repo := RepositoryContext{
		ResourceType:   "ecr-repository",
		RepositoryArn:  "arn:aws:ecr:us-east-1:123456789012:repository/test",
		RepositoryName: "test",
		ScanOnPush:     true,
		Tags:           map[string]string{"env": "prod"},
	}
	m, err := repo.ToOPAInput()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m["resource_type"] != "ecr-repository" {
		t.Errorf("resource_type: want ecr-repository, got %v", m["resource_type"])
	}
	if m["scan_on_push"] != true {
		t.Errorf("scan_on_push: want true, got %v", m["scan_on_push"])
	}
}

// Ensure ScanNotFoundException is distinguishable from other errors.
func TestFetchImages_NonScanError(t *testing.T) {
	now := time.Now().UTC()
	pushedAt := now.Add(-1 * 24 * time.Hour)

	mock := noopPerRepoMock()
	mock.describeImages = func(_ context.Context, _ *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
		return &ecr.DescribeImagesOutput{
			ImageDetails: []types.ImageDetail{{ImageDigest: aws.String("sha256:dddd"), ImagePushedAt: &pushedAt}},
		}, nil
	}
	mock.describeImageScanFindings = func(_ context.Context, _ *ecr.DescribeImageScanFindingsInput, _ ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
		return nil, errors.New("some other error")
	}

	f := newTestFetcher(mock)
	images, err := f.FetchImages(context.Background(), "us-east-1", []string{"my-repo"}, "123456789012", 90)
	if err != nil {
		t.Fatalf("unexpected error (non-scan errors should be logged, not returned): %v", err)
	}
	// Image should still be returned with default scan status
	if len(images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(images))
	}
}
