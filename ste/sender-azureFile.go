// Copyright © Microsoft <wastore@microsoft.com>
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

package ste

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/directory"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/file"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/fileerror"
	filesas "github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/service"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azfile/share"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-storage-azcopy/v10/common"
)

type URLHolder interface {
	URL() string
}

// azureFileSenderBase implements both IFolderSender and (most of) IFileSender.
// Why implement both interfaces in the one type, even though they are largely unrelated? Because it
// makes functions like newAzureFilesUploader easier to reason about, since they always return the same type.
// It may also make it easier to describe what's needed when supporting an new backend - e.g. "to send to a new back end
// you need a sender that implements IFileSender and, if the back end is folder aware, it should also implement IFolderSender"
// (The alternative would be to have the likes of newAzureFilesUploader call sip.EntityType and return a different type
// if the entity type is folder).
type azureFileSenderBase struct {
	jptm            IJobPartTransferMgr
	fileOrDirClient URLHolder
	shareClient     *share.Client
	serviceClient *service.Client
	chunkSize    int64
	numChunks    uint32
	pacer        pacer
	ctx          context.Context
	sip          ISourceInfoProvider
	// Headers and other info that we will apply to the destination
	// object. For S2S, these come from the source service.
	// When sending local data, they are computed based on
	// the properties of the local file
	headersToApply  file.HTTPHeaders
	smbPropertiesToApply file.SMBProperties
	permissionsToApply file.Permissions
	metadataToApply common.Metadata
}

func newAzureFileSenderBase(jptm IJobPartTransferMgr, destination string, pacer pacer, sip ISourceInfoProvider) (*azureFileSenderBase, error) {
	info := jptm.Info()

	// compute chunk size (irrelevant but harmless for folders)
	// If the given chunk Size for the Job is greater than maximum file chunk size i.e 4 MB
	// then chunk size will be 4 MB.
	chunkSize := info.BlockSize
	if chunkSize > common.DefaultAzureFileChunkSize {
		chunkSize = common.DefaultAzureFileChunkSize
		if jptm.ShouldLog(common.LogWarning) {
			jptm.Log(common.LogWarning,
				fmt.Sprintf("Block size %d larger than maximum file chunk size, 4 MB chunk size used", info.BlockSize))
		}
	}

	// compute num chunks (irrelevant but harmless for folders)
	numChunks := getNumChunks(info.SourceSize, chunkSize)

	// due to the REST parity feature added in 2019-02-02, the File APIs are no longer backward compatible
	// so we must use the latest SDK version to stay safe
	// TODO: Should we get rid of this one?

	props, err := sip.Properties()
	if err != nil {
		return nil, err
	}

	fileURLParts, err := file.ParseURL(destination)
	if err != nil {
		return nil, err
	}
	shareName := fileURLParts.ShareName
	shareSnapshot := fileURLParts.ShareSnapshot
	directoryOrFilePath := fileURLParts.DirectoryOrFilePath
	// Strip any non-service related things away
	fileURLParts.ShareName = ""
	fileURLParts.ShareSnapshot = ""
	fileURLParts.DirectoryOrFilePath = ""
	serviceClient := common.CreateFileServiceClient(fileURLParts.String(), jptm.CredentialInfo(), jptm.CredentialOpOptions(), jptm.ClientOptions())

	shareClient := serviceClient.NewShareClient(shareName)
	if shareSnapshot != "" {
		shareClient, err = shareClient.WithSnapshot(shareSnapshot)
		if err != nil {
			return nil, err
		}
	}

	var client URLHolder
	if info.IsFolderPropertiesTransfer() {
		if directoryOrFilePath == "" {
			client = shareClient.NewRootDirectoryClient()
		} else {
			client = shareClient.NewDirectoryClient(directoryOrFilePath)
		}
	} else {
		client = shareClient.NewRootDirectoryClient().NewFileClient(directoryOrFilePath)
	}

	return &azureFileSenderBase{
		jptm:            jptm,
		serviceClient: serviceClient,
		shareClient: shareClient,
		fileOrDirClient: client,
		chunkSize:       chunkSize,
		numChunks:       numChunks,
		pacer:           pacer,
		ctx:             jptm.Context(),
		headersToApply:  props.SrcHTTPHeaders.ToFileHTTPHeaders(),
		smbPropertiesToApply: file.SMBProperties{},
		permissionsToApply: file.Permissions{},
		sip:             sip,
		metadataToApply: props.SrcMetadata,
	}, nil
}

func (u *azureFileSenderBase) getFileClient() *file.Client {
	return u.fileOrDirClient.(*file.Client)
}

func (u *azureFileSenderBase) getDirectoryClient() *directory.Client {
	return u.fileOrDirClient.(*directory.Client)
}

func (u *azureFileSenderBase) ChunkSize() int64 {
	return u.chunkSize
}

func (u *azureFileSenderBase) NumChunks() uint32 {
	return u.numChunks
}

func (u *azureFileSenderBase) RemoteFileExists() (bool, time.Time, error) {
	props, err := u.getFileClient().GetProperties(u.ctx, nil)
	return remoteObjectExists(filePropertiesResponseAdapter{props}, err)
}

func (u *azureFileSenderBase) Prologue(state common.PrologueState) (destinationModified bool) {
	jptm := u.jptm
	info := jptm.Info()

	destinationModified = true

	if jptm.ShouldInferContentType() {
		// sometimes, specifically when reading local files, we have more info
		// about the file type at this time than what we had before
		u.headersToApply.ContentType = state.GetInferredContentType(u.jptm)
	}

	stage, err := u.addPermissionsToHeaders(info, u.getFileClient().URL())
	if err != nil {
		jptm.FailActiveSend(stage, err)
		return
	}

	stage, err = u.addSMBPropertiesToHeaders(info)
	if err != nil {
		jptm.FailActiveSend(stage, err)
		return
	}

	// Turn off readonly at creation time (because if its set at creation time, we won't be
	// able to upload any data to the file!). We'll set it in epilogue, if necessary.
	creationProperties := u.smbPropertiesToApply
	if creationProperties.Attributes != nil {
		creationProperties.Attributes.ReadOnly = false
	}

	err = u.DoWithOverrideReadOnly(u.ctx,
		func() (interface{}, error) {
			return u.getFileClient().Create(u.ctx, info.SourceSize, &file.CreateOptions{HTTPHeaders: &u.headersToApply, Permissions: &u.permissionsToApply, SMBProperties: &creationProperties, Metadata: u.metadataToApply})
		},
		u.fileOrDirClient,
		u.jptm.GetForceIfReadOnly())

	if fileerror.HasCode(err, fileerror.ParentNotFound) {
		// Create the parent directories of the file. Note share must be existed, as the files are listed from share or directory.
		jptm.Log(common.LogError, fmt.Sprintf("%s: %s \n AzCopy going to create parent directories of the Azure files", fileerror.ParentNotFound, err.Error()))
		err = AzureFileParentDirCreator{}.CreateParentDirToRoot(u.ctx, u.getFileClient(), u.serviceClient, u.jptm.GetFolderCreationTracker())
		if err != nil {
			u.jptm.FailActiveUpload("Creating parent directory", err)
		}

		// retrying file creation
		err = u.DoWithOverrideReadOnly(u.ctx,
			func() (interface{}, error) {
				return u.getFileClient().Create(u.ctx, info.SourceSize, &file.CreateOptions{
					HTTPHeaders:  &u.headersToApply,
					SMBProperties: &creationProperties,
					Permissions:  &u.permissionsToApply,
					Metadata: u.metadataToApply,
				})
			},
			u.fileOrDirClient,
			u.jptm.GetForceIfReadOnly())
	}

	if err != nil {
		jptm.FailActiveUpload("Creating file", err)
		return
	}

	return
}

// DoWithOverrideReadOnly performs the given action, and forces it to happen even if the target is read only.
// NOTE that all SMB attributes (and other headers?) on the target will be lost, so only use this if you don't need them any more
// (e.g. you are about to delete the resource, or you are going to reset the attributes/headers)
func (u *azureFileSenderBase) DoWithOverrideReadOnly(ctx context.Context, action func() (interface{}, error), targetFileOrDir URLHolder, enableForcing bool) error {
	// try the action
	_, err := action()

	if fileerror.HasCode(err, fileerror.ParentNotFound, fileerror.ShareNotFound) {
		return err
	}
	failedAsReadOnly := false
	if fileerror.HasCode(err, fileerror.ReadOnlyAttribute) {
		failedAsReadOnly = true
	}
	if !failedAsReadOnly {
		return err
	}

	// did fail as readonly, but forcing is not enabled
	if !enableForcing {
		return errors.New("target is readonly. To force the action to proceed, add --force-if-read-only to the command line")
	}

	// did fail as readonly, and forcing is enabled
	if f, ok := targetFileOrDir.(*file.Client); ok {
		h := file.HTTPHeaders{}
		_, err = f.SetHTTPHeaders(ctx, &file.SetHTTPHeadersOptions{
			HTTPHeaders: &h,
			SMBProperties: &file.SMBProperties{
				// clear the attributes
				Attributes: &file.NTFSFileAttributes{None: true},
			},
		})
	} else if d, ok := targetFileOrDir.(*directory.Client); ok {
		// this code path probably isn't used, since ReadOnly (in Windows file systems at least)
		// only applies to the files in a folder, not to the folder itself. But we'll leave the code here, for now.
		_, err = d.SetProperties(ctx, &directory.SetPropertiesOptions{
			FileSMBProperties: &file.SMBProperties{
				// clear the attributes
				Attributes: &file.NTFSFileAttributes{None: true},
			},
		})
	} else {
		err = errors.New("cannot remove read-only attribute from unknown target type")
	}
	if err != nil {
		return err
	}

	// retry the action
	_, err = action()
	return err
}

func (u *azureFileSenderBase) addPermissionsToHeaders(info TransferInfo, destURL string) (stage string, err error) {
	if !info.PreserveSMBPermissions.IsTruthy() {
		return "", nil
	}

	// Prepare to transfer SDDLs from the source.
	if sddlSIP, ok := u.sip.(ISMBPropertyBearingSourceInfoProvider); ok {
		// If both sides are Azure Files...
		if fSIP, ok := sddlSIP.(*fileSourceInfoProvider); ok {

			srcURLParts, err := file.ParseURL(info.Source)
			common.PanicIfErr(err)
			dstURLParts, err := file.ParseURL(destURL)
			common.PanicIfErr(err)

			// and happen to be the same account and share, we can get away with using the same key and save a trip.
			if srcURLParts.Host == dstURLParts.Host && srcURLParts.ShareName == dstURLParts.ShareName {
				u.permissionsToApply.PermissionKey = &fSIP.cachedPermissionKey
			}
		}

		// If we didn't do the workaround, then let's get the SDDL and put it later.
		if u.permissionsToApply.PermissionKey == nil || *u.permissionsToApply.PermissionKey == "" {
			pString, err := sddlSIP.GetSDDL()

			// Sending "" to the service is invalid, but the service will return it sometimes (e.g. on file shares)
			// Thus, we'll let the files SDK fill in "inherit" for us, so the service is happy.
			if pString != "" {
				u.permissionsToApply.Permission = &pString
			}

			if err != nil {
				return "Getting permissions", err
			}
		}
	}

	if u.permissionsToApply.Permission != nil && len(*u.permissionsToApply.Permission) > filesServiceMaxSDDLSize {
		sipm := u.jptm.SecurityInfoPersistenceManager()
		pkey, err := sipm.PutSDDL(*u.permissionsToApply.Permission, u.shareClient)
		u.permissionsToApply.PermissionKey = &pkey
		if err != nil {
			return "Putting permissions", err
		}

		ePermString := ""
		u.permissionsToApply.Permission = &ePermString
	}
	return "", nil
}

func (u *azureFileSenderBase) addSMBPropertiesToHeaders(info TransferInfo) (stage string, err error) {
	if !info.PreserveSMBInfo {
		return "", nil
	}
	if smbSIP, ok := u.sip.(ISMBPropertyBearingSourceInfoProvider); ok {
		smbProps, err := smbSIP.GetSMBProperties()

		if err != nil {
			return "Obtaining SMB properties", err
		}

		fromTo := u.jptm.FromTo()
		if fromTo.From() == common.ELocation.File() { // Files SDK can panic when the service hands it something unexpected!
			defer func() { // recover from potential panics and output raw properties for debug purposes
				if panicerr := recover(); panicerr != nil {
					stage = "Reading SMB properties"

					attr, _ := smbProps.FileAttributes()
					lwt := smbProps.FileLastWriteTime()
					fct := smbProps.FileCreationTime()

					err = fmt.Errorf("failed to read SMB properties (%w)! Raw data: attr: `%s` lwt: `%s`, fct: `%s`", err, attr, lwt, fct)
				}
			}()
		}

		attribs, _ := smbProps.FileAttributes()
		u.smbPropertiesToApply.Attributes = attribs

		if info.ShouldTransferLastWriteTime() {
			lwTime := smbProps.FileLastWriteTime()
			u.smbPropertiesToApply.LastWriteTime = &lwTime
		}

		creationTime := smbProps.FileCreationTime()
		u.smbPropertiesToApply.CreationTime = &creationTime
	}
	return "", nil
}

func (u *azureFileSenderBase) Epilogue() {
	// always set the SMB info again after the file content has been uploaded, for the following reasons:
	//   0. File attributes such as readOnly and archive need to be passed through another Set Properties call.
	//   1. The syntax for SMB permissions are slightly different for create call vs update call.
	//      This is not trivial but the Files Team has explicitly told us to perform this extra set call.
	//   2. The service started updating the last-write-time in March 2021 when the file is modified.
	//      So when we uploaded the ranges, we've unintentionally changed the last-write-time.
	if u.jptm.IsLive() && u.jptm.Info().PreserveSMBInfo {
		// This is an extra round trip, but we can live with that for these relatively rare cases
		_, err := u.getFileClient().SetHTTPHeaders(u.ctx, &file.SetHTTPHeadersOptions{
			HTTPHeaders: &u.headersToApply,
			Permissions: &u.permissionsToApply,
			SMBProperties: &u.smbPropertiesToApply,
		})
		if err != nil {
			u.jptm.FailActiveSend("Applying final attribute settings", err)
		}
	}
}

func (u *azureFileSenderBase) Cleanup() {
	jptm := u.jptm

	// Cleanup
	if jptm.IsDeadInflight() {
		// transfer was either failed or cancelled
		// the file created in share needs to be deleted, since it's
		// contents will be at an unknown stage of partial completeness
		deletionContext, cancelFn := context.WithTimeout(context.WithValue(context.Background(), ServiceAPIVersionOverride, DefaultServiceApiVersion), 2*time.Minute)
		defer cancelFn()
		_, err := u.getFileClient().Delete(deletionContext, nil)
		if err != nil {
			jptm.Log(common.LogError, fmt.Sprintf("error deleting the (incomplete) file %s. Failed with error %s", u.fileOrDirClient.URL(), err.Error()))
		}
	}
}

func (u *azureFileSenderBase) GetDestinationLength() (int64, error) {
	prop, err := u.getFileClient().GetProperties(u.ctx, nil)

	if err != nil {
		return -1, err
	}

	if prop.ContentLength == nil {
		return -1, fmt.Errorf("destination content length not returned")
	}
	return *prop.ContentLength, nil
}

func (u *azureFileSenderBase) EnsureFolderExists() error {
	return AzureFileParentDirCreator{}.CreateDirToRoot(u.ctx, u.shareClient, u.getDirectoryClient(), u.jptm.GetFolderCreationTracker())
}

func (u *azureFileSenderBase) SetFolderProperties() error {
	info := u.jptm.Info()

	_, err := u.addPermissionsToHeaders(info, u.getDirectoryClient().URL())
	if err != nil {
		return err
	}

	_, err = u.addSMBPropertiesToHeaders(info)
	if err != nil {
		return err
	}

	_, err = u.getDirectoryClient().SetMetadata(u.ctx, &directory.SetMetadataOptions{Metadata: u.metadataToApply})
	if err != nil {
		return err
	}

	err = u.DoWithOverrideReadOnly(u.ctx,
		func() (interface{}, error) {
			return u.getDirectoryClient().SetProperties(u.ctx, &directory.SetPropertiesOptions{
			FileSMBProperties: &u.smbPropertiesToApply,
			FilePermissions: &u.permissionsToApply,
		}) },
		u.fileOrDirClient,
		u.jptm.GetForceIfReadOnly())
	return err
}

func (u *azureFileSenderBase) DirUrlToString() string {
	directoryURL := u.getDirectoryClient().URL()
	rawURL, err := url.Parse(directoryURL)
	common.PanicIfErr(err)
	rawURL.RawQuery = ""
	// To avoid encoding/decoding
	rawURL.RawPath = ""
	return rawURL.String()
}

// namespace for functions related to creating parent directories in Azure File
// to avoid free floating global funcs
type AzureFileParentDirCreator struct{}

// getParentDirectoryClient gets parent directory client of a path.
func (AzureFileParentDirCreator) getParentDirectoryClient(uh URLHolder, serviceClient *service.Client) (*share.Client, *directory.Client, error) {
	rawURL, _ := url.Parse(uh.URL())
	rawURL.Path = rawURL.Path[:strings.LastIndex(rawURL.Path, "/")]
	directoryURLParts, err := filesas.ParseURL(rawURL.String())
	if err != nil {
		return nil, nil, err
	}
	directoryOrFilePath := directoryURLParts.DirectoryOrFilePath
	shareClient := serviceClient.NewShareClient(directoryURLParts.ShareName)
	if directoryURLParts.ShareSnapshot != "" {
		shareClient, err = shareClient.WithSnapshot(directoryURLParts.ShareSnapshot)
		if err != nil {
			return nil, nil, err
		}
	}
	return shareClient, shareClient.NewRootDirectoryClient().NewSubdirectoryClient(directoryOrFilePath), nil
}

// verifyAndHandleCreateErrors handles create errors, StatusConflict is ignored, as specific level directory could be existing.
// Report http.StatusForbidden, as user should at least have read and write permission of the destination,
// and there is no permission on directory level, i.e. create directory is a general permission for each level directories for Azure file.
func (AzureFileParentDirCreator) verifyAndHandleCreateErrors(err error) error {
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == http.StatusConflict { // Note the ServiceCode actually be AuthenticationFailure when share failed to be created, if want to create share as well.
			return nil
		}
		return err
	}

	return nil
}

// splitWithoutToken splits string with a given token, and returns split results without token.
func (AzureFileParentDirCreator) splitWithoutToken(str string, token rune) []string {
	return strings.FieldsFunc(str, func(c rune) bool {
		return c == token
	})
}

// CreateParentDirToRoot creates parent directories of the Azure file if file's parent directory doesn't exist.
func (d AzureFileParentDirCreator) CreateParentDirToRoot(ctx context.Context, fileClient *file.Client, serviceClient *service.Client, t FolderCreationTracker) error {
	shareClient, directoryClient, err := d.getParentDirectoryClient(fileClient, serviceClient)
	if err != nil {
		return err
	}
	return d.CreateDirToRoot(ctx, shareClient, directoryClient, t)
}

func (d AzureFileParentDirCreator) CreateDirToRoot(ctx context.Context, shareClient *share.Client, directoryClient *directory.Client, t FolderCreationTracker) error {
	fileURLParts, err := file.ParseURL(directoryClient.URL())
	if err != nil {
		return err
	}
	_, err = directoryClient.GetProperties(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusNotFound || respErr.StatusCode == http.StatusForbidden) {
			// Either the parent directory does not exist, or we may not have read permissions.
			// Try to create the parent directories. Split directories as segments.
			segments := d.splitWithoutToken(fileURLParts.DirectoryOrFilePath, '/')
			currentDirectoryClient := shareClient.NewRootDirectoryClient() // Share directory should already exist, doesn't support creating share
			// Try to create the directories
			for i := 0; i < len(segments); i++ {
				currentDirectoryClient = currentDirectoryClient.NewSubdirectoryClient(segments[i])
				rawURL := currentDirectoryClient.URL()
				recorderURL, err := url.Parse(rawURL)
				if err != nil {
					return err
				}
				recorderURL.RawQuery = ""
				err = t.CreateFolder(recorderURL.String(), func() error {
					_, err := currentDirectoryClient.Create(ctx, nil)
					return err
				})
				if verifiedErr := d.verifyAndHandleCreateErrors(err); verifiedErr != nil {
					return verifiedErr
				}
			}
		} else {
			return err
		}
	}
	// Directly return if parent directory exists.
	return nil
}