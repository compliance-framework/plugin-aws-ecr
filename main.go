package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/container-solutions/plugin-aws-ecr/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger     hclog.Logger
	config     *internal.PluginConfig
	policyData map[string]interface{}
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	rawConfig := req.GetConfig()
	parsedConfig, err := internal.ParseConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	l.config = parsedConfig

	if req.GetPolicyData() != nil {
		l.policyData = req.GetPolicyData().AsMap()
	} else {
		l.policyData = nil
	}

	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "ecr-repository",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "ECR Repository {{ .repository_name }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "AWS ECR private repository {{ .repository_name }}.",
			PurposeTemplate:     "Represents an AWS ECR private repository evaluated for compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "repository_arn"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "repository_arn", Description: "ECR repository ARN"},
				{Key: "repository_name", Description: "ECR repository name"},
			},
		},
		{
			Name:                "ecr-registry",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "ECR Registry {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "AWS ECR account-level registry in {{ .account_id }}/{{ .region }}.",
			PurposeTemplate:     "Represents an AWS ECR registry evaluated for scanning configuration compliance.",
			IdentityLabelKeys:   []string{"account_id", "region"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "registry_id", Description: "ECR registry ID (account ID)"},
			},
		},
		{
			Name:                "ecr-image",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "ECR Image {{ .repository_name }}@{{ .image_digest }} in {{ .account_id }}/{{ .region }}",
			DescriptionTemplate: "Container image {{ .image_digest }} in ECR repository {{ .repository_name }}.",
			PurposeTemplate:     "Represents a container image digest evaluated for vulnerability scan compliance.",
			IdentityLabelKeys:   []string{"account_id", "region", "repository_arn", "image_digest"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "repository_arn", Description: "ECR repository ARN"},
				{Key: "repository_name", Description: "ECR repository name"},
				{Key: "image_digest", Description: "Immutable image digest (sha256:...)"},
			},
		},
	}
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, subjectTemplates)
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()
	activities := make([]*proto.Activity, 0)

	if request == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("eval request is nil")
	}

	lookbackDays := 90
	if l.policyData != nil {
		if v, ok := l.policyData["image_lookback_days"].(float64); ok && v > 0 {
			lookbackDays = int(v)
		}
	}

	// Scope policy paths to each resource type using behavior mapping.
	// Bundles are matched by substring against the policy path, so a bundle
	// named "*ecr-repository-policies*" maps to repository checks, etc.
	defaultBehaviorMapping := map[string][]string{
		"ecr-repository-policies": {"repository"},
		"ecr-registry-policies":   {"registry"},
		"ecr-image-policies":      {"image"},
	}
	policyEval := request.WithDefaultPolicyBehavior(defaultBehaviorMapping)

	repositoryPaths := policyEval.PolicyPathsForBehavior("repository")
	registryPaths   := policyEval.PolicyPathsForBehavior("registry")
	imagePaths      := policyEval.PolicyPathsForBehavior("image")

	dataFetcher := internal.NewDataFetcher(l.logger, l.config)
	policyEvaluator := internal.NewPolicyEvaluator(ctx, l.logger, activities)

	var allEvidences []*proto.Evidence
	var evalErrors error

	for _, region := range l.config.Regions {
		// Fetch repositories only when at least one bundle covers repository or image checks.
		var repos []internal.RepositoryContext
		if len(repositoryPaths) > 0 || len(imagePaths) > 0 {
			r, err := dataFetcher.FetchRepositories(ctx, region)
			if err != nil {
				return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("region %s: fetching repositories: %w", region, err)
			}
			repos = internal.FilterByAccounts(r, l.config.Accounts)
		}

		for _, repo := range repos {
			evidences, err := policyEvaluator.EvalRepository(ctx, repo, repositoryPaths, l.policyData, l.config.PolicyLabels)
			allEvidences = append(allEvidences, evidences...)
			if err != nil {
				evalErrors = errors.Join(evalErrors, fmt.Errorf("evaluating repository %s: %w", repo.RepositoryName, err))
			}
		}

		// CONFIG — registry scanning check (one per region, skipped for image-only runs)
		if len(registryPaths) > 0 {
			registry, err := dataFetcher.FetchRegistryConfig(ctx, region)
			if err != nil {
				evalErrors = errors.Join(evalErrors, fmt.Errorf("region %s: fetching registry scanning config: %w", region, err))
			} else {
				evidences, err := policyEvaluator.EvalRegistry(ctx, registry, registryPaths, l.policyData, l.config.PolicyLabels)
				allEvidences = append(allEvidences, evidences...)
				if err != nil {
					evalErrors = errors.Join(evalErrors, fmt.Errorf("evaluating registry %s/%s: %w", registry.AccountID, region, err))
				}
			}
		}

		// DYNAMIC — image scan checks (skipped for config-only runs)
		if len(imagePaths) > 0 && len(repos) > 0 {
			// Group repos by account so each account's images are fetched with the
			// correct accountID — using repos[0].AccountID for all repos is wrong
			// when multiple accounts are configured.
			reposByAccount := make(map[string][]string)
			for _, r := range repos {
				reposByAccount[r.AccountID] = append(reposByAccount[r.AccountID], r.RepositoryName)
			}
			for accID, names := range reposByAccount {
				images, err := dataFetcher.FetchImages(ctx, region, names, accID, lookbackDays)
				if err != nil {
					return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("region %s account %s: fetching images: %w", region, accID, err)
				}
				for _, image := range images {
					evidences, err := policyEvaluator.EvalImage(ctx, image, imagePaths, l.policyData, l.config.PolicyLabels)
					allEvidences = append(allEvidences, evidences...)
					if err != nil {
						evalErrors = errors.Join(evalErrors, fmt.Errorf("evaluating image %s@%s: %w", image.RepositoryName, image.ImageDigest, err))
					}
				}
			}
		}
	}

	if err := apiHelper.CreateEvidence(ctx, allEvidences); err != nil {
		l.logger.Error("Error creating evidence", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	if evalErrors != nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, evalErrors
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	logger.Debug("initiating plugin-aws-ecr")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
