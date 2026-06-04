package internal

import (
	"context"
	"errors"
	"fmt"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type PolicyEvaluator struct {
	ctx            context.Context
	logger         hclog.Logger
	stepActivities []*proto.Activity
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{ctx: ctx, logger: logger, stepActivities: stepActivities}
}

// EvalRepository evaluates all policyPaths against a repository and returns Evidence.
func (pe *PolicyEvaluator) EvalRepository(ctx context.Context, repo RepositoryContext, policyPaths []string, policyData map[string]interface{}, extraLabels map[string]string) ([]*proto.Evidence, error) {
	input, err := repo.ToOPAInput()
	if err != nil {
		return nil, fmt.Errorf("serialising repository %s: %w", repo.RepositoryArn, err)
	}

	componentID := "common-components/aws-ecr-repository"
	inventoryID := fmt.Sprintf("aws-ecr-repository/%s/%s/%s", repo.AccountID, repo.Region, repo.RepositoryName)

	labels := MergeMaps(extraLabels, repositoryBaseLabels(), map[string]string{
		"repository_arn":  repo.RepositoryArn,
		"resource_arn":    repo.RepositoryArn,
		"repository_name": repo.RepositoryName,
		"region":          repo.Region,
		"account_id":      repo.AccountID,
	})

	actors := ecrActors("AWS ECR Plugin")
	components := []*proto.Component{
		{
			Identifier:  componentID,
			Type:        "service",
			Title:       "Amazon Elastic Container Registry",
			Description: "Amazon ECR is a fully managed container registry that makes it easy to store, manage, share, and deploy container images and artifacts.",
			Purpose:     "To store and manage container images with access controls, image scanning, and lifecycle policies.",
		},
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier: inventoryID,
			Type:       "container-registry",
			Title:      fmt.Sprintf("ECR Repository [%s]", repo.RepositoryName),
			Props: []*proto.Property{
				{Name: "repository_arn", Value: repo.RepositoryArn},
				{Name: "repository_name", Value: repo.RepositoryName},
				{Name: "region", Value: repo.Region},
				{Name: "encryption_type", Value: repo.EncryptionType},
				{Name: "image_tag_immutability", Value: repo.ImageTagImmutability},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{{Identifier: componentID}},
		},
	}
	subjects := []*proto.Subject{
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: componentID},
		{Type: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM, Identifier: inventoryID},
	}

	return pe.runPolicies(ctx, policyPaths, input, labels, subjects, components, inventory, actors, policyData, repo.RepositoryName)
}

// EvalRegistry evaluates all policyPaths against a registry (account+region) and returns Evidence.
func (pe *PolicyEvaluator) EvalRegistry(ctx context.Context, registry RegistryContext, policyPaths []string, policyData map[string]interface{}, extraLabels map[string]string) ([]*proto.Evidence, error) {
	input, err := registry.ToOPAInput()
	if err != nil {
		return nil, fmt.Errorf("serialising registry %s/%s: %w", registry.AccountID, registry.Region, err)
	}

	componentID := "common-components/aws-ecr-registry"
	inventoryID := fmt.Sprintf("aws-ecr-registry/%s/%s", registry.AccountID, registry.Region)

	labels := MergeMaps(extraLabels, registryBaseLabels(), map[string]string{
		"registry_id":  registry.RegistryID,
		"region":       registry.Region,
		"account_id":   registry.AccountID,
		"resource_arn": fmt.Sprintf("arn:%s:ecr:%s:%s:registry", arnPartition(registry.Region), registry.Region, registry.AccountID),
	})

	actors := ecrActors("AWS ECR Plugin")
	components := []*proto.Component{
		{
			Identifier:  componentID,
			Type:        "service",
			Title:       "Amazon ECR Registry",
			Description: "The ECR registry is the account-level container image registry that hosts all private repositories.",
			Purpose:     "To provide account-level scanning configuration and access controls across all ECR repositories.",
		},
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier: inventoryID,
			Type:       "container-registry",
			Title:      fmt.Sprintf("ECR Registry [%s/%s]", registry.AccountID, registry.Region),
			Props: []*proto.Property{
				{Name: "registry_id", Value: registry.RegistryID},
				{Name: "region", Value: registry.Region},
				{Name: "registry_scan_type", Value: registry.RegistryScanType},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{{Identifier: componentID}},
		},
	}
	subjects := []*proto.Subject{
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: componentID},
		{Type: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM, Identifier: inventoryID},
	}

	return pe.runPolicies(ctx, policyPaths, input, labels, subjects, components, inventory, actors, policyData, fmt.Sprintf("%s/%s", registry.AccountID, registry.Region))
}

// EvalImage evaluates all policyPaths against an image digest and returns Evidence.
func (pe *PolicyEvaluator) EvalImage(ctx context.Context, image ImageContext, policyPaths []string, policyData map[string]interface{}, extraLabels map[string]string) ([]*proto.Evidence, error) {
	input, err := image.ToOPAInput()
	if err != nil {
		return nil, fmt.Errorf("serialising image %s: %w", image.ImageDigest, err)
	}

	componentID := "common-components/aws-ecr-image"
	digestShort := image.ImageDigest
	if len(digestShort) > 19 {
		digestShort = digestShort[:19]
	}
	inventoryID := fmt.Sprintf("aws-ecr-image/%s/%s/%s/%s", image.AccountID, image.Region, image.RepositoryName, image.ImageDigest)

	labels := MergeMaps(extraLabels, imageBaseLabels(), map[string]string{
		"repository_arn":  image.RepositoryArn,
		"resource_arn":    image.RepositoryArn + "@" + image.ImageDigest,
		"repository_name": image.RepositoryName,
		"image_digest":    image.ImageDigest,
		"region":          image.Region,
		"account_id":      image.AccountID,
	})

	actors := ecrActors("AWS ECR Plugin")
	components := []*proto.Component{
		{
			Identifier:  componentID,
			Type:        "artifact",
			Title:       "Amazon ECR Container Image",
			Description: "A container image stored in Amazon ECR, subject to vulnerability scanning and lifecycle policies.",
			Purpose:     "To provide a scannable, immutable artifact reference for container workload compliance evaluation.",
		},
	}
	inventory := []*proto.InventoryItem{
		{
			Identifier: inventoryID,
			Type:       "container-image",
			Title:      fmt.Sprintf("ECR Image [%s@%s]", image.RepositoryName, digestShort),
			Props: []*proto.Property{
				{Name: "repository_arn", Value: image.RepositoryArn},
				{Name: "image_digest", Value: image.ImageDigest},
				{Name: "scan_status", Value: image.ScanStatus},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{{Identifier: componentID}},
		},
	}
	subjects := []*proto.Subject{
		{Type: proto.SubjectType_SUBJECT_TYPE_COMPONENT, Identifier: componentID},
		{Type: proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM, Identifier: inventoryID},
	}

	return pe.runPolicies(ctx, policyPaths, input, labels, subjects, components, inventory, actors, policyData, fmt.Sprintf("%s@%s", image.RepositoryName, digestShort))
}

func (pe *PolicyEvaluator) runPolicies(
	ctx context.Context,
	policyPaths []string,
	input map[string]interface{},
	labels map[string]string,
	subjects []*proto.Subject,
	components []*proto.Component,
	inventory []*proto.InventoryItem,
	actors []*proto.OriginActor,
	policyData map[string]interface{},
	titleSuffix string,
) ([]*proto.Evidence, error) {
	var accumulatedErrors error
	evidences := make([]*proto.Evidence, 0)

	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			pe.logger,
			labels,
			subjects,
			components,
			inventory,
			actors,
			pe.stepActivities,
			policyData,
		)
		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		for _, ev := range evidence {
			ev.Title = fmt.Sprintf("%s [%s]", ev.GetTitle(), titleSuffix)
		}
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, perr)
		}
	}
	return evidences, accumulatedErrors
}

func ecrActors(pluginTitle string) []*proto.OriginActor {
	return []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: fmt.Sprintf("Continuous Compliance Framework - %s", pluginTitle),
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-aws-ecr",
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework AWS ECR Plugin"),
				},
			},
		},
	}
}

// repositoryBaseLabels returns stable identity labels for ECR repository evidence.
// SeededUUID derives the evidence UUID from ALL labels — changing any key breaks evidence continuity.
func repositoryBaseLabels() map[string]string {
	return map[string]string{
		"provider": "aws",
		"type":     "ecr-repository",
	}
}

// registryBaseLabels returns stable identity labels for ECR registry evidence.
func registryBaseLabels() map[string]string {
	return map[string]string{
		"provider": "aws",
		"type":     "ecr-registry",
	}
}

// imageBaseLabels returns stable identity labels for ECR image evidence.
func imageBaseLabels() map[string]string {
	return map[string]string{
		"provider": "aws",
		"type":     "ecr-image",
	}
}
