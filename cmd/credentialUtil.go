// Copyright © 2017 Microsoft <wastore@microsoft.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// This file contains credential utils used only in cmd module.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-storage-azcopy/v10/jobsAdmin"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/minio/minio-go/pkg/s3utils"

	"github.com/Azure/azure-pipeline-go/pipeline"
	"github.com/Azure/azure-storage-azcopy/v10/common"
	"github.com/Azure/azure-storage-azcopy/v10/ste"
)

var once sync.Once
var autoOAuth sync.Once

// only one UserOAuthTokenManager should exists in azcopy-v2 process in cmd(FE) module for current user.
// (given appAppPathFolder is mapped to current user)
var currentUserOAuthTokenManager *common.UserOAuthTokenManager

const oauthLoginSessionCacheKeyName = "AzCopyOAuthTokenCache"
const oauthLoginSessionCacheServiceName = "AzCopyV10"
const oauthLoginSessionCacheAccountName = "AzCopyOAuthTokenCache"

// GetUserOAuthTokenManagerInstance gets or creates OAuthTokenManager for current user.
// Note: Currently, only support to have TokenManager for one user mapping to one tenantID.
func GetUserOAuthTokenManagerInstance() *common.UserOAuthTokenManager {
	once.Do(func() {
		if common.AzcopyJobPlanFolder == "" {
			panic("invalid state, AzcopyJobPlanFolder should not be an empty string")
		}
		currentUserOAuthTokenManager = common.NewUserOAuthTokenManagerInstance(common.CredCacheOptions{
			DPAPIFilePath: common.AzcopyJobPlanFolder,
			KeyName:       oauthLoginSessionCacheKeyName,
			ServiceName:   oauthLoginSessionCacheServiceName,
			AccountName:   oauthLoginSessionCacheAccountName,
		})
	})

	return currentUserOAuthTokenManager
}

/*
 * GetInstanceOAuthTokenInfo returns OAuth token, obtained by auto-login,
 * for current instance of AzCopy.
 */
func GetOAuthTokenManagerInstance() (*common.UserOAuthTokenManager, error) {
	var err error
	autoOAuth.Do(func() {
		var lca loginCmdArgs
		autoLoginType := strings.ToUpper(glcm.GetEnvironmentVariable(common.EEnvironmentVariable.AutoLoginType()))
		if autoLoginType == "" {
			glcm.Info("Autologin not specified.")
			return
		}

		if autoLoginType != "SPN" && autoLoginType != "MSI" && autoLoginType != "DEVICE" {
			glcm.Error("Invalid Auto-login type specified.")
			return
		}

		if tenantID := glcm.GetEnvironmentVariable(common.EEnvironmentVariable.TenantID()); tenantID != "" {
			lca.tenantID = tenantID
		}

		if endpoint := glcm.GetEnvironmentVariable(common.EEnvironmentVariable.AADEndpoint()); endpoint != "" {
			lca.aadEndpoint = endpoint
		}

		// Fill up lca
		switch glcm.GetEnvironmentVariable(common.EEnvironmentVariable.AutoLoginType()) {
		case "SPN":
			lca.applicationID = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.ApplicationID())
			lca.certPath = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.CertificatePath())
			lca.certPass = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.CertificatePassword())
			lca.clientSecret = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.ClientSecret())
			lca.servicePrincipal = true

		case "MSI":
			lca.identityClientID = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.ManagedIdentityClientID())
			lca.identityObjectID = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.ManagedIdentityObjectID())
			lca.identityResourceID = glcm.GetEnvironmentVariable(common.EEnvironmentVariable.ManagedIdentityResourceString())
			lca.identity = true

		case "DEVICE":
			lca.identity = false
		}

		lca.persistToken = false
		if err = lca.process(); err != nil {
			glcm.Error(fmt.Sprintf("Failed to perform Auto-login: %v.", err.Error()))
		}
	})

	if err != nil {
		return nil, err
	}

	return GetUserOAuthTokenManagerInstance(), nil
}

var announceOAuthTokenOnce sync.Once

func oAuthTokenExists() (oauthTokenExists bool) {
	// Note: Environment variable for OAuth token should only be used in testing, or the case user clearly now how to protect
	// the tokens
	if common.EnvVarOAuthTokenInfoExists() {
		announceOAuthTokenOnce.Do(
			func() {
				glcm.Info(fmt.Sprintf("%v is set.", common.EnvVarOAuthTokenInfo)) // Log the case when env var is set, as it's rare case.
			},
		)
		oauthTokenExists = true
	}

	uotm, err := GetOAuthTokenManagerInstance()
	if err != nil {
		oauthTokenExists = false
		return
	}

	if hasCachedToken, err := uotm.HasCachedToken(); hasCachedToken {
		oauthTokenExists = true
	} else if err != nil { //nolint:staticcheck
		// Log the error if fail to get cached token, as these are unhandled errors, and should not influence the logic flow.
		// Uncomment for debugging.
		// glcm.Info(fmt.Sprintf("No cached token found, %v", err))
	}

	return
}

type rawFromToInfo struct {
	fromTo                    common.FromTo
	source, destination       string
	sourceSAS, destinationSAS string // Standalone SAS which might be provided
}

const trustedSuffixesNameAAD = "trusted-microsoft-suffixes"
const trustedSuffixesAAD = "*.core.windows.net;*.core.chinacloudapi.cn;*.core.cloudapi.de;*.core.usgovcloudapi.net;*.storage.azure.net"

// checkAuthSafeForTarget checks our "implicit" auth types (those that pick up creds from the environment
// or a prior login) to make sure they are only being used in places where we know those auth types are safe.
// This prevents, for example, us accidentally sending OAuth creds to some place they don't belong
func checkAuthSafeForTarget(ct common.CredentialType, resource, extraSuffixesAAD string, resourceType common.Location) error {

	getSuffixes := func(list string, extras string) []string {
		extras = strings.Trim(extras, " ")
		if extras != "" {
			list += ";" + extras
		}
		return strings.Split(list, ";")
	}

	isResourceInSuffixList := func(suffixes []string) (string, bool) {
		u, err := url.Parse(resource)
		if err != nil {
			return "<unparsable>", false
		}
		host := strings.ToLower(u.Host)

		for _, s := range suffixes {
			s = strings.Trim(s, " *") // trim *.foo to .foo
			s = strings.ToLower(s)
			if strings.HasSuffix(host, s) {
				return host, true
			}
		}
		return host, false
	}

	switch ct {
	case common.ECredentialType.Unknown(),
		 common.ECredentialType.NoAuth(),
		common.ECredentialType.Anonymous():
		// these auth types don't pick up anything from environment vars, so they are not the focus of this routine
		return nil
	case common.ECredentialType.OAuthToken(),
		common.ECredentialType.MDOAuthToken(),
		common.ECredentialType.SharedKey():
		// Files doesn't currently support OAuth, but it's a valid azure endpoint anyway, so it'll pass the check.
		if resourceType != common.ELocation.Blob() && resourceType != common.ELocation.BlobFS() && resourceType != common.ELocation.File() {
			// There may be a reason for files->blob to specify this.
			if resourceType == common.ELocation.Local() {
				return nil
			}

			return fmt.Errorf("azure OAuth authentication to %s is not enabled in AzCopy", resourceType.String())
		}

		// these are Azure auth types, so make sure the resource is known to be in Azure
		domainSuffixes := getSuffixes(trustedSuffixesAAD, extraSuffixesAAD)
		if host, ok := isResourceInSuffixList(domainSuffixes); !ok {
			return fmt.Errorf(
				"the URL requires authentication. If this URL is in fact an Azure service, you can enable Azure authentication to %s. "+
					"To enable, view the documentation for "+
					"the parameter --%s, by running 'AzCopy copy --help'. BUT if this URL is not an Azure service, do NOT enable Azure authentication to it. "+
					"Instead, see if the URL host supports authentication by way of a token that can be included in the URL's query string",
				// E.g. CDN apparently supports a non-SAS type of token as noted here: https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth#setting-up-token-authentication
				// Including such a token in the URL will cause AzCopy to see it as a "public" URL (since the URL on its own will pass
				// our "isPublic" access tests, which run before this routine).
				host, trustedSuffixesNameAAD)
		}

	case common.ECredentialType.S3AccessKey():
		if resourceType != common.ELocation.S3() {
			//noinspection ALL
			return fmt.Errorf("S3 access key authentication to %s is not enabled in AzCopy", resourceType.String())
		}

		// just check with minio. No need to have our own list of S3 domains, since minio effectively
		// has that list already, we can't talk to anything outside that list because minio won't let us,
		// and the parsing of s3 URL is non-trivial.  E.g. can't just look for the ending since
		// something like https://someApi.execute-api.someRegion.amazonaws.com is AWS but is a customer-
		// written code, not S3.
		ok := false
		host := "<unparsable url>"
		u, err := url.Parse(resource)
		if err == nil {
			host = u.Host
			parts, err := common.NewS3URLParts(*u) // strip any leading bucket name from URL, to get an endpoint we can pass to s3utils
			if err == nil {
				u, err := url.Parse("https://" + parts.Endpoint)
				ok = err == nil && s3utils.IsAmazonEndpoint(*u)
			}
		}

		if !ok {
			return fmt.Errorf(
				"s3 authentication to %s is not currently supported in AzCopy", host)
		}
	case common.ECredentialType.GoogleAppCredentials():
		if resourceType != common.ELocation.GCP() {
			return fmt.Errorf("Google Application Credentials to %s is not valid", resourceType.String())
		}

		u, err := url.Parse(resource)
		if err == nil {
			host := u.Host
			_, err := common.NewGCPURLParts(*u)
			if err != nil {
				return fmt.Errorf("GCP authentication to %s is not currently supported", host)
			}
		}
	default:
		panic("unknown credential type")
	}

	return nil
}

func logAuthType(ct common.CredentialType, location common.Location, isSource bool) {
	if location == common.ELocation.Unknown() {
		return // nothing to log
	} else if location.IsLocal() {
		return // don't log local ones, no point
	} else if ct == common.ECredentialType.Anonymous() {
		return // don't log these either (too cluttered and auth type is obvious from the URL)
	}

	resource := "destination"
	if isSource {
		resource = "source"
	}
	name := ct.String()
	if ct == common.ECredentialType.OAuthToken() {
		name = "Azure AD" // clarify the name to something users will recognize
	} else if ct == common.ECredentialType.MDOAuthToken() {
		name = "Azure AD (Managed Disk)"
	}
	message := fmt.Sprintf("Authenticating to %s using %s", resource, name)
	if _, exists := authMessagesAlreadyLogged.Load(message); !exists {
		authMessagesAlreadyLogged.Store(message, struct{}{}) // dedup because source is auth'd by both enumerator and STE
		if jobsAdmin.JobsAdmin != nil {
			jobsAdmin.JobsAdmin.LogToJobLog(message, pipeline.LogInfo)
		}
		glcm.Info(message)
	}
}

var authMessagesAlreadyLogged = &sync.Map{}

// ==============================================================================================
// pipeline factory methods
// ==============================================================================================
func createClientOptions(logLevel pipeline.LogLevel, trailingDot *common.TrailingDotOption, from *common.Location) azcore.ClientOptions {
	logOptions := ste.LogOptions{}
	if azcopyScanningLogger != nil {
		logOptions.LogOptions = pipeline.LogOptions{
			Log:       azcopyScanningLogger.Log,
			ShouldLog: func(level pipeline.LogLevel) bool { return level <= logLevel },
		}
	}
	return ste.NewClientOptions(policy.RetryOptions{
		MaxRetries:    ste.UploadMaxTries,
		TryTimeout:    ste.UploadTryTimeout,
		RetryDelay:    ste.UploadRetryDelay,
		MaxRetryDelay: ste.UploadMaxRetryDelay,
	}, policy.TelemetryOptions{
		ApplicationID: glcm.AddUserAgentPrefix(common.UserAgent),
	}, ste.NewAzcopyHTTPClient(frontEndMaxIdleConnectionsPerHost), nil, logOptions, trailingDot, from)
}

const frontEndMaxIdleConnectionsPerHost = http.DefaultMaxIdleConnsPerHost


//getDestinationCredential assumes 'resource' is destination,
// and finds appropriate auth type for it.
func getDestinationCredential(ctx context.Context,
							  loc common.Location,
							  resource common.ResourceString,
							  cpk common.CpkOptions) (
							  common.CredentialType, error) {
	switch loc {
	case common.ELocation.Local(), common.ELocation.Pipe():
		return common.ECredentialType.NoAuth(), nil
	case common.ELocation.S3(), common.ELocation.GCP():
		return common.ECredentialType.Unknown(),
					common.EAzError.UnsupportedDestination()
	}

	mdAccount := false
	if loc == common.ELocation.Blob() {
		uri, _ := url.Parse(resource.Value)
		if strings.HasPrefix(uri.Host, "md-") {
			mdAccount = true
		}
	}

	// The destinations can be Blob, BlobFS and Files. If we have
	// SAS, we'll always use it.
	if resource.SAS != "" && !mdAccount {
		return common.ECredentialType.Anonymous(), nil
	}

	// Files supports only SAS
	if loc == common.ELocation.File() {
		return common.ECredentialType.Unknown(), errAzureFilesSupportsOnlySAS
	}

	// We've either BLob or BlobFS here
	if mdAccount {
		blobURL, err := resource.String()
		if err != nil {
			return common.ECredentialType.Unknown(), err
		}

		if requiresToken, err := requiresBearerToken(ctx, blobURL, cpk); err != nil {
			return common.ECredentialType.Unknown(), err
		} else if requiresToken && oAuthTokenExists() {
			return common.ECredentialType.MDOAuthToken(), nil
		} else if requiresToken {
			return common.ECredentialType.Unknown(), errLoginMDOauthMissing
		}

		return common.ECredentialType.Anonymous(), nil
	}

	if oAuthTokenExists() {
		return common.ECredentialType.OAuthToken(), nil
	}

	return common.ECredentialType.Unknown(), errLoginCredsMissing 
}

//getSourceCredentialType assumes 'resource' is source and
//attempts to find an authType
func getSrcCredential(ctx context.Context,
					  loc common.Location,
					  resource common.ResourceString,
					  cpk common.CpkOptions) (common.CredentialType, error) {
	switch loc {
	case common.ELocation.Local(), common.ELocation.Pipe():
		return common.ECredentialType.NoAuth(), nil
	case common.ELocation.S3():
		accessKeyID := glcm.GetEnvironmentVariable(common.EEnvironmentVariable.AWSAccessKeyID())
		secretAccessKey := glcm.GetEnvironmentVariable(common.EEnvironmentVariable.AWSSecretAccessKey())
		if accessKeyID == "" || secretAccessKey == "" {
			return common.ECredentialType.S3PublicBucket(), nil
		}
		return common.ECredentialType.S3AccessKey(), nil
	case common.ELocation.GCP():
		googleAppCredentials := glcm.GetEnvironmentVariable(common.EEnvironmentVariable.GoogleAppCredentials())
		if googleAppCredentials == "" {
			return common.ECredentialType.Unknown(), errors.New("GOOGLE_APPLICATION_CREDENTIALS environment variable must be set before using GCP transfer feature")
		}
		return common.ECredentialType.GoogleAppCredentials(), nil
	default:
	}

	// Only Blob location can be mdAccount or be public.
	if loc == common.ELocation.Blob() {
		uri, _ := url.Parse(resource.Value)
		mdAccount := strings.HasPrefix(uri.Host, "md-")

		blobURL, err := resource.String()
		if err != nil {
			return common.ECredentialType.Unknown(), err
		}

		// Md accounts are not public
		if !mdAccount && blobResourceIsPublic(ctx, blobURL, cpk) {
			return common.ECredentialType.Anonymous(), nil
		}

		if requiresToken, err := requiresBearerToken(ctx, blobURL, cpk); err != nil {
			return common.ECredentialType.Unknown(), err
		} else if requiresToken && oAuthTokenExists() {
			return common.ECredentialType.MDOAuthToken(), nil
		} else if requiresToken {
			return common.ECredentialType.Unknown(), errLoginMDOauthMissing
		}
	}

	// We are left with Blob, blobFS and Files

	// If we have SAS, we'll always use it.
	if resource.SAS != "" {
		return common.ECredentialType.Anonymous(), nil
	}

	if loc == common.ELocation.File() {
		return common.ECredentialType.Unknown(), errAzureFilesSupportsOnlySAS
	}

	if oAuthTokenExists() {
		glcm.Info("Authentication: If the source and destination accounts are in the same AAD tenant "+
		          "& the user/spn/msi has appropriate permissions on both, the source SAS token is not"+
				  " required and OAuth can be used round-trip.")
		return common.ECredentialType.OAuthToken(), nil
	}

	return common.ECredentialType.Unknown(), errLoginCredsMissing
}

func requiresBearerToken(ctx context.Context, blobURL string, cpkOptions common.CpkOptions) (bool, error) {
	var respErr *azcore.ResponseError
	// We assume it to be a blob endpoint always
	credInfo := common.CredentialInfo{CredentialType: common.ECredentialType.Anonymous()}
	blobClient := common.CreateBlobClient(blobURL, credInfo, nil, policy.ClientOptions{})
	_, err := blobClient.GetProperties(ctx, &blob.GetPropertiesOptions{CPKInfo: cpkOptions.GetCPKInfo()})

	if err == nil {
		return false, nil
	}

	if !errors.As(err, &respErr) ||
		(respErr.StatusCode != http.StatusUnauthorized && respErr.StatusCode != http.StatusForbidden) {// *sometimes* the service can return 403s
		return false, fmt.Errorf("unexpected response for managed disk authorization check: %w", err)
	}

	challenge := respErr.RawResponse.Header.Get("WWW-Authenticate")
	return strings.Contains(challenge, common.MDResource), nil
}

func blobResourceIsPublic(ctx context.Context, blobResourceURL string, cpkOptions common.CpkOptions) bool {
		// Either blob is public or blob is public. Virtual directories are
		// public if container itself is public
		bURLParts, err := blob.ParseURL(blobResourceURL)
		if err != nil {
			return false
		}
		
		if bURLParts.ContainerName == "" || strings.Contains(bURLParts.ContainerName, "*") {
			// Service level searches can't possibly be public.
			return false
		}

		bURLParts.BlobName = ""
		bURLParts.Snapshot = ""
		bURLParts.VersionID = ""
		credInfo := common.CredentialInfo{CredentialType: common.ECredentialType.Anonymous()}
		containerClient := common.CreateContainerClient(bURLParts.String(), credInfo, nil, policy.ClientOptions{})

		if _, err := containerClient.GetProperties(ctx, nil); err == nil {
			return true // Container is public.
		}
		// TODO: log error here.

		blobClient := common.CreateBlobClient(blobResourceURL, credInfo, nil, policy.ClientOptions{})
		if _, err := blobClient.GetProperties(ctx, &blob.GetPropertiesOptions{CPKInfo: cpkOptions.GetCPKInfo()}); err == nil {
			return true
		}

		return false
}
