package velocity

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"
)

// S3 Error Code constants
const (
	S3ErrAccessDenied                = "AccessDenied"
	S3ErrAccountProblem              = "AccountProblem"
	S3ErrBucketAlreadyExists         = "BucketAlreadyExists"
	S3ErrBucketAlreadyOwnedByYou     = "BucketAlreadyOwnedByYou"
	S3ErrBucketNotEmpty              = "BucketNotEmpty"
	S3ErrEntityTooLarge              = "EntityTooLarge"
	S3ErrEntityTooSmall              = "EntityTooSmall"
	S3ErrExpiredToken                = "ExpiredToken"
	S3ErrIllegalVersioningConfig     = "IllegalVersioningConfigurationException"
	S3ErrIncompleteBody              = "IncompleteBody"
	S3ErrInternalError               = "InternalError"
	S3ErrInvalidAccessKeyId          = "InvalidAccessKeyId"
	S3ErrInvalidArgument             = "InvalidArgument"
	S3ErrInvalidBucketName           = "InvalidBucketName"
	S3ErrInvalidBucketState          = "InvalidBucketState"
	S3ErrInvalidDigest               = "InvalidDigest"
	S3ErrInvalidLocationConstraint   = "InvalidLocationConstraint"
	S3ErrInvalidObjectState          = "InvalidObjectState"
	S3ErrInvalidPart                 = "InvalidPart"
	S3ErrInvalidPartOrder            = "InvalidPartOrder"
	S3ErrInvalidRange                = "InvalidRange"
	S3ErrInvalidRequest              = "InvalidRequest"
	S3ErrInvalidSecurity             = "InvalidSecurity"
	S3ErrInvalidTag                  = "InvalidTag"
	S3ErrInvalidURI                  = "InvalidURI"
	S3ErrKeyTooLongError             = "KeyTooLongError"
	S3ErrMalformedACLError           = "MalformedACLError"
	S3ErrMalformedXML                = "MalformedXML"
	S3ErrMetadataTooLarge            = "MetadataTooLarge"
	S3ErrMethodNotAllowed            = "MethodNotAllowed"
	S3ErrMissingContentLength        = "MissingContentLength"
	S3ErrMissingRequestBodyError     = "MissingRequestBodyError"
	S3ErrMissingSecurityHeader       = "MissingSecurityHeader"
	S3ErrNoSuchBucket                = "NoSuchBucket"
	S3ErrNoSuchKey                   = "NoSuchKey"
	S3ErrNoSuchUpload                = "NoSuchUpload"
	S3ErrNoSuchVersion               = "NoSuchVersion"
	S3ErrNotImplemented              = "NotImplemented"
	S3ErrPreconditionFailed          = "PreconditionFailed"
	S3ErrRequestTimeTooSkewed        = "RequestTimeTooSkewed"
	S3ErrServiceUnavailable          = "ServiceUnavailable"
	S3ErrSignatureDoesNotMatch       = "SignatureDoesNotMatch"
	S3ErrTooManyBuckets              = "TooManyBuckets"
	S3ErrInvalidEncryptionAlgorithm  = "InvalidEncryptionAlgorithmError"
	S3ErrNoSuchBucketPolicy          = "NoSuchBucketPolicy"
	S3ErrNoSuchTagSet                = "NoSuchTagSet"
	S3ErrXAmzContentSHA256Mismatch   = "XAmzContentSHA256Mismatch"
)

// S3 error code to HTTP status mapping
var s3ErrorHTTPStatus = map[string]int{
	S3ErrAccessDenied:               http.StatusForbidden,
	S3ErrBucketAlreadyExists:        http.StatusConflict,
	S3ErrBucketAlreadyOwnedByYou:    http.StatusConflict,
	S3ErrBucketNotEmpty:             http.StatusConflict,
	S3ErrEntityTooLarge:             http.StatusBadRequest,
	S3ErrEntityTooSmall:             http.StatusBadRequest,
	S3ErrExpiredToken:               http.StatusBadRequest,
	S3ErrIncompleteBody:             http.StatusBadRequest,
	S3ErrInternalError:              http.StatusInternalServerError,
	S3ErrInvalidAccessKeyId:         http.StatusForbidden,
	S3ErrInvalidArgument:            http.StatusBadRequest,
	S3ErrInvalidBucketName:          http.StatusBadRequest,
	S3ErrInvalidBucketState:         http.StatusConflict,
	S3ErrInvalidDigest:              http.StatusBadRequest,
	S3ErrInvalidLocationConstraint:  http.StatusBadRequest,
	S3ErrInvalidObjectState:         http.StatusForbidden,
	S3ErrInvalidPart:                http.StatusBadRequest,
	S3ErrInvalidPartOrder:           http.StatusBadRequest,
	S3ErrInvalidRange:               http.StatusRequestedRangeNotSatisfiable,
	S3ErrInvalidRequest:             http.StatusBadRequest,
	S3ErrInvalidSecurity:            http.StatusForbidden,
	S3ErrInvalidTag:                 http.StatusBadRequest,
	S3ErrInvalidURI:                 http.StatusBadRequest,
	S3ErrKeyTooLongError:            http.StatusBadRequest,
	S3ErrMalformedACLError:          http.StatusBadRequest,
	S3ErrMalformedXML:               http.StatusBadRequest,
	S3ErrMetadataTooLarge:           http.StatusBadRequest,
	S3ErrMethodNotAllowed:           http.StatusMethodNotAllowed,
	S3ErrMissingContentLength:       http.StatusLengthRequired,
	S3ErrMissingRequestBodyError:    http.StatusBadRequest,
	S3ErrMissingSecurityHeader:      http.StatusBadRequest,
	S3ErrNoSuchBucket:               http.StatusNotFound,
	S3ErrNoSuchKey:                  http.StatusNotFound,
	S3ErrNoSuchUpload:               http.StatusNotFound,
	S3ErrNoSuchVersion:              http.StatusNotFound,
	S3ErrNotImplemented:             http.StatusNotImplemented,
	S3ErrPreconditionFailed:         http.StatusPreconditionFailed,
	S3ErrRequestTimeTooSkewed:       http.StatusForbidden,
	S3ErrServiceUnavailable:         http.StatusServiceUnavailable,
	S3ErrSignatureDoesNotMatch:      http.StatusForbidden,
	S3ErrTooManyBuckets:             http.StatusBadRequest,
	S3ErrInvalidEncryptionAlgorithm: http.StatusBadRequest,
	S3ErrNoSuchBucketPolicy:         http.StatusNotFound,
	S3ErrNoSuchTagSet:               http.StatusNotFound,
	S3ErrXAmzContentSHA256Mismatch:  http.StatusBadRequest,
}

// S3ErrorHTTPStatus returns the HTTP status code for the given S3 error code.
func S3ErrorHTTPStatus(code string) int {
	if status, ok := s3ErrorHTTPStatus[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// S3Error represents an S3 XML error response.
type S3Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestId string   `xml:"RequestId"`
}

// Error implements the error interface.
func (e *S3Error) Error() string {
	return fmt.Sprintf("S3Error: Code=%s, Message=%s, Resource=%s, RequestId=%s",
		e.Code, e.Message, e.Resource, e.RequestId)
}

// HTTPStatus returns the HTTP status code for this error.
func (e *S3Error) HTTPStatus() int {
	return S3ErrorHTTPStatus(e.Code)
}

// MarshalXML marshals the S3Error to XML bytes.
func (e *S3Error) MarshalXMLBytes() ([]byte, error) {
	return xml.Marshal(e)
}

// NewS3Error creates a new S3Error with the given parameters.
func NewS3Error(code, message, resource, requestId string) *S3Error {
	return &S3Error{
		Code:      code,
		Message:   message,
		Resource:  resource,
		RequestId: requestId,
	}
}

// --- S3 Timestamp Helpers ---

// S3TimeFormat is the time format used in S3 responses (ISO 8601).
const S3TimeFormat = "2006-01-02T15:04:05.000Z"

// S3Time wraps time.Time to provide S3-compatible XML marshaling.
type S3Time struct {
	time.Time
}

// MarshalXML formats the time as S3-compatible ISO 8601.
func (t S3Time) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(t.Time.UTC().Format(S3TimeFormat), start)
}

// --- Bucket List Response ---

// ListBucketsResult is the XML response for listing buckets.
type ListBucketsResult struct {
	XMLName xml.Name     `xml:"ListAllMyBucketsResult"`
	Xmlns   string       `xml:"xmlns,attr"`
	Owner   S3Owner      `xml:"Owner"`
	Buckets S3BucketList `xml:"Buckets"`
}

// S3Owner represents an S3 bucket/object owner.
type S3Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// S3BucketList is a wrapper for the list of buckets.
type S3BucketList struct {
	Bucket []S3BucketEntry `xml:"Bucket"`
}

// S3BucketEntry represents a single bucket in a list response.
type S3BucketEntry struct {
	Name         string `xml:"Name"`
	CreationDate S3Time `xml:"CreationDate"`
}

// --- ListObjectsV2 Response ---

// ListObjectsV2Result is the XML response for ListObjectsV2.
type ListObjectsV2Result struct {
	XMLName               xml.Name       `xml:"ListBucketResult"`
	Xmlns                 string         `xml:"xmlns,attr"`
	Name                  string         `xml:"Name"`
	Prefix                string         `xml:"Prefix"`
	Delimiter             string         `xml:"Delimiter,omitempty"`
	MaxKeys               int            `xml:"MaxKeys"`
	KeyCount              int            `xml:"KeyCount"`
	IsTruncated           bool           `xml:"IsTruncated"`
	ContinuationToken     string         `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string         `xml:"NextContinuationToken,omitempty"`
	StartAfter            string         `xml:"StartAfter,omitempty"`
	EncodingType          string         `xml:"EncodingType,omitempty"`
	Contents              []S3Object     `xml:"Contents,omitempty"`
	CommonPrefixes        []CommonPrefix `xml:"CommonPrefixes,omitempty"`
}

// S3Object represents a single object in a listing response.
type S3Object struct {
	Key          string  `xml:"Key"`
	LastModified S3Time  `xml:"LastModified"`
	ETag         string  `xml:"ETag"`
	Size         int64   `xml:"Size"`
	StorageClass string  `xml:"StorageClass"`
	Owner        S3Owner `xml:"Owner,omitempty"`
}

// CommonPrefix represents a common prefix (virtual directory) in a listing.
type CommonPrefix struct {
	Prefix string `xml:"Prefix"`
}

// --- ListObjectVersions Response ---

// ListObjectVersionsResult is the XML response for listing object versions.
type ListObjectVersionsResult struct {
	XMLName             xml.Name               `xml:"ListVersionsResult"`
	Xmlns               string                 `xml:"xmlns,attr"`
	Name                string                 `xml:"Name"`
	Prefix              string                 `xml:"Prefix"`
	Delimiter           string                 `xml:"Delimiter,omitempty"`
	MaxKeys             int                    `xml:"MaxKeys"`
	IsTruncated         bool                   `xml:"IsTruncated"`
	KeyMarker           string                 `xml:"KeyMarker"`
	VersionIdMarker     string                 `xml:"VersionIdMarker"`
	NextKeyMarker       string                 `xml:"NextKeyMarker,omitempty"`
	NextVersionIdMarker string                 `xml:"NextVersionIdMarker,omitempty"`
	Versions            []S3ObjectVersion      `xml:"Version,omitempty"`
	DeleteMarkers       []S3DeleteMarkerEntry  `xml:"DeleteMarker,omitempty"`
	CommonPrefixes      []CommonPrefix         `xml:"CommonPrefixes,omitempty"`
}

// S3ObjectVersion represents a version entry.
type S3ObjectVersion struct {
	Key          string  `xml:"Key"`
	VersionId    string  `xml:"VersionId"`
	IsLatest     bool    `xml:"IsLatest"`
	LastModified S3Time  `xml:"LastModified"`
	ETag         string  `xml:"ETag"`
	Size         int64   `xml:"Size"`
	StorageClass string  `xml:"StorageClass"`
	Owner        S3Owner `xml:"Owner,omitempty"`
}

// S3DeleteMarkerEntry represents a delete marker in version listing.
type S3DeleteMarkerEntry struct {
	Key          string  `xml:"Key"`
	VersionId    string  `xml:"VersionId"`
	IsLatest     bool    `xml:"IsLatest"`
	LastModified S3Time  `xml:"LastModified"`
	Owner        S3Owner `xml:"Owner,omitempty"`
}

// --- Copy Object Response ---

// CopyObjectResult is the XML response for CopyObject.
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	LastModified S3Time   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// --- Multipart Upload Responses ---

// InitiateMultipartUploadResult is the XML response for initiating a multipart upload.
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

// CompleteMultipartUploadResult is the XML response for completing a multipart upload.
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// CompletedMultipartUpload represents the request body for completing a multipart upload.
type CompletedMultipartUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

// CompletedPart represents a part in a complete multipart upload request.
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// ListMultipartUploadsResult is the XML response for listing multipart uploads.
type ListMultipartUploadsResult struct {
	XMLName            xml.Name              `xml:"ListMultipartUploadsResult"`
	Xmlns              string                `xml:"xmlns,attr"`
	Bucket             string                `xml:"Bucket"`
	KeyMarker          string                `xml:"KeyMarker"`
	UploadIdMarker     string                `xml:"UploadIdMarker"`
	NextKeyMarker      string                `xml:"NextKeyMarker,omitempty"`
	NextUploadIdMarker string                `xml:"NextUploadIdMarker,omitempty"`
	MaxUploads         int                   `xml:"MaxUploads"`
	IsTruncated        bool                  `xml:"IsTruncated"`
	Uploads            []MultipartUploadInfo `xml:"Upload,omitempty"`
	Prefix             string                `xml:"Prefix,omitempty"`
	Delimiter          string                `xml:"Delimiter,omitempty"`
	CommonPrefixes     []CommonPrefix        `xml:"CommonPrefixes,omitempty"`
}

// MultipartUploadInfo represents a multipart upload in a list response.
type MultipartUploadInfo struct {
	Key          string  `xml:"Key"`
	UploadId     string  `xml:"UploadId"`
	Initiator    S3Owner `xml:"Initiator"`
	Owner        S3Owner `xml:"Owner"`
	StorageClass string  `xml:"StorageClass"`
	Initiated    S3Time  `xml:"Initiated"`
}

// ListPartsResult is the XML response for listing parts.
type ListPartsResult struct {
	XMLName              xml.Name      `xml:"ListPartsResult"`
	Xmlns                string        `xml:"xmlns,attr"`
	Bucket               string        `xml:"Bucket"`
	Key                  string        `xml:"Key"`
	UploadId             string        `xml:"UploadId"`
	PartNumberMarker     int           `xml:"PartNumberMarker"`
	NextPartNumberMarker int           `xml:"NextPartNumberMarker"`
	MaxParts             int           `xml:"MaxParts"`
	IsTruncated          bool          `xml:"IsTruncated"`
	Initiator            S3Owner       `xml:"Initiator"`
	Owner                S3Owner       `xml:"Owner"`
	StorageClass         string        `xml:"StorageClass"`
	Parts                []S3PartEntry `xml:"Part,omitempty"`
}

// S3PartEntry represents a part in a list parts response.
type S3PartEntry struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified S3Time `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// --- Bucket Configuration Types ---

// CreateBucketConfiguration represents the XML body for creating a bucket.
type CreateBucketConfiguration struct {
	XMLName            xml.Name `xml:"CreateBucketConfiguration"`
	LocationConstraint string   `xml:"LocationConstraint,omitempty"`
}

// VersioningConfiguration represents the bucket versioning configuration.
type VersioningConfiguration struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	Xmlns     string   `xml:"xmlns,attr,omitempty"`
	Status    string   `xml:"Status,omitempty"`    // "Enabled" or "Suspended"
	MFADelete string   `xml:"MfaDelete,omitempty"` // "Enabled" or "Disabled"
}

// --- Object Tagging ---

// Tagging represents object tags.
type S3Tagging struct {
	XMLName xml.Name  `xml:"Tagging"`
	Xmlns   string    `xml:"xmlns,attr,omitempty"`
	TagSet  S3TagSet  `xml:"TagSet"`
}

// S3TagSet is a set of tags.
type S3TagSet struct {
	Tags []S3Tag `xml:"Tag"`
}

// S3Tag represents a single tag.
type S3Tag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// --- ACL ---

// AccessControlPolicy represents an S3 ACL.
type AccessControlPolicy struct {
	XMLName           xml.Name          `xml:"AccessControlPolicy"`
	Xmlns             string            `xml:"xmlns,attr,omitempty"`
	Owner             S3Owner           `xml:"Owner"`
	AccessControlList AccessControlList `xml:"AccessControlList"`
}

// AccessControlList contains grants.
type AccessControlList struct {
	Grants []S3Grant `xml:"Grant"`
}

// S3Grant represents a single ACL grant.
type S3Grant struct {
	Grantee    S3Grantee `xml:"Grantee"`
	Permission string    `xml:"Permission"` // FULL_CONTROL, WRITE, READ, READ_ACP, WRITE_ACP
}

// S3Grantee represents a grantee in an ACL.
type S3Grantee struct {
	XMLName     xml.Name `xml:"Grantee"`
	Xmlns       string   `xml:"xmlns:xsi,attr,omitempty"`
	XsiType     string   `xml:"xsi:type,attr,omitempty"`
	ID          string   `xml:"ID,omitempty"`
	DisplayName string   `xml:"DisplayName,omitempty"`
	URI         string   `xml:"URI,omitempty"`
}

// --- Delete Objects ---

// DeleteRequest represents the XML body for multi-object delete.
type S3DeleteRequest struct {
	XMLName xml.Name         `xml:"Delete"`
	Quiet   bool             `xml:"Quiet"`
	Objects []S3ObjectToDelete `xml:"Object"`
}

// S3ObjectToDelete represents an object to delete.
type S3ObjectToDelete struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
}

// DeleteResult represents the XML response for multi-object delete.
type S3DeleteResult struct {
	XMLName xml.Name          `xml:"DeleteResult"`
	Xmlns   string            `xml:"xmlns,attr"`
	Deleted []S3DeletedObject `xml:"Deleted,omitempty"`
	Errors  []S3DeleteError   `xml:"Error,omitempty"`
}

// S3DeletedObject represents a successfully deleted object.
type S3DeletedObject struct {
	Key       string `xml:"Key"`
	VersionId string `xml:"VersionId,omitempty"`
}

// S3DeleteError represents an error deleting an object.
type S3DeleteError struct {
	Key       string `xml:"Key"`
	Code      string `xml:"Code"`
	Message   string `xml:"Message"`
	VersionId string `xml:"VersionId,omitempty"`
}

// --- S3 Constants ---

// Canned ACL constants
const (
	S3ACLPrivate                = "private"
	S3ACLPublicRead             = "public-read"
	S3ACLPublicReadWrite        = "public-read-write"
	S3ACLAuthenticatedRead      = "authenticated-read"
	S3ACLAwsExecRead            = "aws-exec-read"
	S3ACLBucketOwnerRead        = "bucket-owner-read"
	S3ACLBucketOwnerFullControl = "bucket-owner-full-control"
	S3ACLLogDeliveryWrite       = "log-delivery-write"
)

// S3 Storage class constants
const (
	S3StorageStandard           = "STANDARD"
	S3StorageReducedRedundancy  = "REDUCED_REDUNDANCY"
	S3StorageStandardIA         = "STANDARD_IA"
	S3StorageOnezoneIA          = "ONEZONE_IA"
	S3StorageIntelligentTiering = "INTELLIGENT_TIERING"
	S3StorageGlacier            = "GLACIER"
	S3StorageDeepArchive        = "DEEP_ARCHIVE"
	S3StorageGlacierIR          = "GLACIER_IR"
)

// S3 versioning states
const (
	S3VersioningEnabled   = "Enabled"
	S3VersioningSuspended = "Suspended"
)

// S3 permission constants
const (
	S3PermFullControl = "FULL_CONTROL"
	S3PermWrite       = "WRITE"
	S3PermRead        = "READ"
	S3PermReadACP     = "READ_ACP"
	S3PermWriteACP    = "WRITE_ACP"
)

// S3 XML namespace
const S3XMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// S3 maximum key length
const S3MaxKeyLength = 1024

// S3 maximum number of tags per object
const S3MaxTagsPerObject = 10

// S3 maximum tag key length
const S3MaxTagKeyLength = 128

// S3 maximum tag value length
const S3MaxTagValueLength = 256

// S3 maximum number of buckets per account
const S3MaxBucketsPerAccount = 100

// S3 minimum part size (5 MB, except last part)
const S3MinPartSize = 5 * 1024 * 1024

// S3 maximum part size (5 GB)
const S3MaxPartSize = 5 * 1024 * 1024 * 1024

// S3 maximum number of parts
const S3MaxPartCount = 10000

// S3 maximum object size (5 TB)
const S3MaxObjectSize = 5 * 1024 * 1024 * 1024 * 1024

// S3 presigned URL max expiration (7 days)
const S3MaxPresignExpiry = 7 * 24 * time.Hour
