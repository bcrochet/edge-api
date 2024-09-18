package commit

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/redhatinsights/edge-api/config"
	"github.com/redhatinsights/edge-api/pkg/clients/pulp"
	"github.com/redhatinsights/edge-api/pkg/models"

	log "github.com/sirupsen/logrus"
)

// Store imports an OSTree repo into Pulp
func Store(ctx context.Context, orgID string, edgeRepoID uint, sourceURL string) error {
	// create a domain with the Org ID
	domainName, err := domainCreate(ctx, orgID)
	if err != nil {
		return err
	}

	// get a pulp service based on the specific domain
	pserv, err := pulp.NewPulpServiceWithDomain(ctx, domainName)
	if err != nil {
		return err
	}

	// Import the commit tarfile into an initial Pulp file repo
	fileRepo, err := fileRepoImport(ctx, pserv, sourceURL)
	if err != nil {
		log.WithContext(ctx).Error("Error importing tarfile to initial pulp file repository")
		return err
	}
	// create an OSTree repository in Pulp
	// TODO: check for an existing OSTree repo for image commit versions > 1 and add the commit
	ostreeRepoName, pulpHref, err := ostreeRepoCreate(ctx, pserv, orgID, edgeRepoID)
	if err != nil {
		log.WithContext(ctx).Error("Error creating pulp ostree repository")
		return err
	}
	log.WithContext(ctx).Info("Pulp OSTree Repo created with Content Guard and Distribution")

	if err := ostreeRepoImport(ctx, pserv, ostreeRepoName, pulpHref, sourceURL, fileRepo); err != nil {
		log.WithContext(ctx).Error("Error importing tarfile into pulp ostree repository")

		return err
	}
	log.WithContext(ctx).Info("Image Builder commit tarfile imported into pulp ostree repo from pulp file repo")

	return nil
}

// Create creates a domain for a specific org if one does not already exist
func domainCreate(ctx context.Context, orgID string) (string, error) {
	name := fmt.Sprintf("em%sd", orgID)
	pulpDefaultService, err := pulp.NewPulpServiceDefaultDomain(ctx)
	if err != nil {
		return name, err
	}

	domains, err := pulpDefaultService.DomainsList(ctx, name)
	if err != nil {
		log.WithContext(ctx).WithFields(log.Fields{
			"domain_name": name,
			"error":       err.Error(),
		}).Error("Error listing pulp domains")
		return name, err
	}

	if len(domains) > 1 {
		log.WithContext(ctx).WithFields(log.Fields{
			"name":    name,
			"domains": domains,
		}).Error("More than one domain matches name")
		return name, errors.New("More than one domain matches name")
	}

	if len(domains) == 0 {
		createdDomain, err := pulpDefaultService.DomainsCreate(ctx, name)
		if err != nil {
			log.WithContext(ctx).WithField("error", err.Error()).Error("Error creating pulp domain")
			return name, err
		}

		domainUUID := pulp.ScanUUID(createdDomain.PulpHref)

		log.WithContext(ctx).WithFields(log.Fields{
			"domain_name": createdDomain.Name,
			"domain_href": createdDomain.PulpHref,
			"domain_uuid": domainUUID,
		}).Info("Created new pulp domain")
	}

	return name, nil
}

type pulpFileRepoImporter interface {
	FileRepositoriesEnsure(context.Context) (string, error)
	FileRepositoriesImport(context.Context, string, string) (string, string, error)
}

type fileRepo struct {
	name     string
	artifact string
	version  string
}

func fileRepoImport(ctx context.Context, pulpService pulpFileRepoImporter, sourceURL string) (fileRepo, error) {
	// get the file repo to initially push the tar artifact
	repo, err := pulpService.FileRepositoriesEnsure(ctx)
	if err != nil {
		return fileRepo{}, err
	}

	log.WithContext(ctx).Info("File repo found or created: ", repo)

	artifact, version, err := pulpService.FileRepositoriesImport(ctx, repo, sourceURL)
	if err != nil {
		return fileRepo{}, err
	}
	log.WithContext(ctx).WithFields(log.Fields{
		"artifact": artifact,
		"version":  version,
	}).Info("Pulp artifact uploaded")

	return fileRepo{repo, artifact, version}, nil
}

type pulpOSTreeRepositoryCreator interface {
	RepositoriesCreate(context.Context, string) (*pulp.OstreeOstreeRepositoryResponse, error)
	ContentGuardEnsure(context.Context, string) (*pulp.CompositeContentGuardResponse, error)
	DistributionsCreate(context.Context, string, string, string, string) (*pulp.OstreeOstreeDistributionResponse, error)
}

// Create creates a new Pulp OSTree repository for a commit
func ostreeRepoCreate(ctx context.Context, pulpService pulpOSTreeRepositoryCreator, orgID string, edgeRepoID uint) (string, string, error) {
	repoName := fmt.Sprintf("repo-%s-%d", orgID, edgeRepoID)

	pulpRepo, err := pulpService.RepositoriesCreate(ctx, repoName)
	if err != nil {
		return repoName, "", err
	}
	pulpHref := *pulpRepo.PulpHref
	log.WithContext(ctx).WithField("pulp_href", pulpHref).Info("Pulp Repository created")

	cg, err := pulpService.ContentGuardEnsure(ctx, orgID)
	if err != nil {
		return repoName, pulpHref, err
	}
	cgPulpHref := *cg.PulpHref
	log.WithContext(ctx).WithFields(log.Fields{
		"contentguard_href": cgPulpHref,
		"contentguard_0":    (*cg.Guards)[0],
		"contentguard_1":    (*cg.Guards)[1],
	}).Info("Pulp Content Guard found or created")

	distribution, err := pulpService.DistributionsCreate(ctx, repoName, repoName, pulpHref, cgPulpHref)
	if err != nil {
		return repoName, pulpHref, err
	}
	log.WithContext(ctx).WithFields(log.Fields{
		"name":      distribution.Name,
		"base_path": distribution.BasePath,
		"base_url":  distribution.BaseUrl,
		"pulp_href": distribution.PulpHref,
	}).Info("Pulp Distribution created")

	return repoName, pulpHref, nil
}

// DistributionURL returns the password embedded distribution URL for a specific repo
func distributionURL(ctx context.Context, distBaseURL string, domain string, repoName string) (string, error) {
	cfg := config.Get()

	prodDistURL, err := url.Parse(distBaseURL)
	if err != nil {
		return "", errors.New("Unable to set user:password for Pulp distribution URL")
	}
	prodDistURL.User = url.UserPassword(cfg.PulpContentUsername, cfg.PulpContentPassword)
	distURL := prodDistURL.String()

	// temporarily handle stage URLs so Image Builder worker can get to stage Pulp
	if strings.Contains(distBaseURL, "stage") {
		stagePulpURL := fmt.Sprintf("%s/api/pulp-content/%s/%s", cfg.PulpURL, domain, repoName)
		stageDistURL, err := url.Parse(stagePulpURL)
		if err != nil {
			return "", errors.New("Unable to set user:password for Pulp distribution URL")
		}
		stageDistURL.User = url.UserPassword(cfg.PulpContentUsername, cfg.PulpContentPassword)

		distURL = stageDistURL.String()
	}

	parsedDistURL, _ := url.Parse(distURL)
	log.WithContext(ctx).WithField("distribution_url", parsedDistURL.Redacted()).Debug("Distribution URL retrieved")

	return distURL, err
}

type pulpOSTreeRepositoryImporter interface {
	RepositoriesImport(context.Context, uuid.UUID, string, string) (*pulp.OstreeOstreeRepositoryResponse, error)
	FileRepositoriesVersionDelete(context.Context, uuid.UUID, int64) error
	Domain() string
}

// Import imports an artifact into the repo and deletes the tarfile artifact
func ostreeRepoImport(ctx context.Context, pulpService pulpOSTreeRepositoryImporter, pulpRepoName string, pulpHref string, baseEdgeRepoURL string, fileRepo fileRepo) error {
	log.WithContext(ctx).Debug("Starting tarfile import into Pulp OSTree repository")
	repoImported, err := pulpService.RepositoriesImport(ctx, pulp.ScanUUID(&pulpHref), "repo", fileRepo.artifact)
	if err != nil {
		return err
	}
	log.WithContext(ctx).Info("Repository imported", *repoImported.PulpHref)

	defer func() {
		if err := pulpService.FileRepositoriesVersionDelete(ctx, pulp.ScanUUID(&fileRepo.version), pulp.ScanRepoFileVersion(&fileRepo.version)); err == nil {
			log.WithContext(ctx).Info("Artifact version deleted", fileRepo.version)
		}
	}()

	edgeRepoURL, err := distributionURL(ctx, baseEdgeRepoURL, pulpService.Domain(), pulpRepoName)
	if err != nil {
		log.WithContext(ctx).WithField("error", err.Error()).Error("Error getting distibution URL for Pulp repo")
	}

	parsedEdgeRepoURL, _ := url.Parse(edgeRepoURL)
	log.WithContext(ctx).WithFields(log.Fields{
		"status":                models.RepoStatusSuccess,
		"repo_distribution_url": parsedEdgeRepoURL.Redacted(),
	}).Debug("Repo import into Pulp complete")

	return nil
}
