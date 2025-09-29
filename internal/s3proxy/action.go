package s3proxy

import (
	"net/http"
	"net/url"
)

func detectS3Action(r *http.Request, bucket, key string) string {
	method := r.Method
	u := r.URL
	q := u.Query()

	if bucket == "" {
		return detectS3ActionRoot(method, q)
	}

	if key == "" {
		return detectS3ActionBucket(method, q)
	}

	hasCopySource := r.Header.Get("x-amz-copy-source") != ""
	return detectS3ActionKey(method, q, hasCopySource)
}

func detectS3ActionRoot(method string, q url.Values) string {
	has := func(name string) bool {
		_, ok := q[name]
		return ok
	}

	switch method {
	case http.MethodGet:
		switch {
		case has("max-directory-buckets"):
			return "ListDirectoryBuckets"
		default:
			return "ListBuckets"
		}
	case http.MethodPut:
		return "CreateBucket"
	default:
		return ""
	}
}

func detectS3ActionBucket(method string, q url.Values) string {
	has := func(name string) bool {
		_, ok := q[name]
		return ok
	}
	val := func(name string) string {
		return q.Get(name)
	}

	switch method {
	case http.MethodHead:
		return "HeadBucket"

	case http.MethodGet:
		switch {
		case has("session"):
			return "CreateSession"
		case has("accelerate"):
			return "GetBucketAccelerateConfiguration"
		case has("acl"):
			return "GetBucketAcl"
		case has("analytics") && has("id"):
			return "GetBucketAnalyticsConfiguration"
		case has("cors"):
			return "GetBucketCors"
		case has("encryption"):
			return "GetBucketEncryption"
		case has("intelligent-tiering") && has("id"):
			return "GetBucketIntelligentTieringConfiguration"
		case has("inventory") && has("id"):
			return "GetBucketInventoryConfiguration"
		case has("lifecycle"):
			//WARN: This matches GetBucketLifecycle and GetBucketLifecycleConfiguration, pick GetBucketLifecycleConfiguration
			return "GetBucketLifecycleConfiguration"
		case has("location"):
			return "GetBucketLocation"
		case has("logging"):
			return "GetBucketLogging"
		case has("metadataConfiguration"):
			return "GetBucketMetadataConfiguration"
		case has("metadataTable"):
			return "GetBucketMetadataTableConfiguration"
		case has("metrics") && has("id"):
			return "GetBucketMetricsConfiguration"
		case has("notification"):
			//WARN: This matches GetBucketNotification and GetBucketNotificationConfiguration, pick GetBucketNotificationConfiguration
			return "GetBucketNotificationConfiguration"
		case has("ownershipControls"):
			return "GetBucketOwnershipControls"
		case has("policy"):
			return "GetBucketPolicy"
		case has("policyStatus"):
			return "GetBucketPolicyStatus"
		case has("replication"):
			return "GetBucketReplication"
		case has("requestPayment"):
			return "GetBucketRequestPayment"
		case has("tagging"):
			return "GetBucketTagging"
		case has("versioning"):
			return "GetBucketVersioning"
		case has("website"):
			return "GetBucketWebsite"

		case has("analytics"):
			return "ListBucketAnalyticsConfigurations"
		case has("intelligent-tiering"):
			return "ListBucketIntelligentTieringConfigurations"
		case has("inventory"):
			return "ListBucketInventoryConfigurations"
		case has("metrics"):
			return "ListBucketMetricsConfigurations"

		case has("uploads"):
			return "ListMultipartUploads"
		case has("versions"):
			return "ListObjectVersions"
		case has("list-type") && val("list-type") == "2":
			return "ListObjectsV2"
		default:
			return "ListObjects"
		}

	case http.MethodPut:
		// Bucket-level PUT -> PutBucket*
		switch {
		case has("accelerate"):
			return "PutBucketAccelerateConfiguration"
		case has("acl"):
			return "PutBucketAcl"
		case has("analytics"):
			return "PutBucketAnalyticsConfiguration"
		case has("cors"):
			return "PutBucketCors"
		case has("encryption"):
			return "PutBucketEncryption"
		case has("intelligent-tiering"):
			return "PutBucketIntelligentTieringConfiguration"
		case has("inventory"):
			return "PutBucketInventoryConfiguration"
		case has("lifecycle"):
			//WARN: This matches PutBucketLifecycle and PutBucketLifecycleConfiguration, pick PutBucketLifecycleConfiguration
			return "PutBucketLifecycleConfiguration"
		case has("logging"):
			return "PutBucketLogging"
		case has("metrics"):
			return "PutBucketMetricsConfiguration"
		case has("notification"):
			return "PutBucketNotification"
		case has("notificationConfiguration"):
			return "PutBucketNotificationConfiguration"
		case has("ownershipControls"):
			return "PutBucketOwnershipControls"
		case has("policy"):
			return "PutBucketPolicy"
		case has("replication"):
			return "PutBucketReplication"
		case has("requestPayment"):
			return "PutBucketRequestPayment"
		case has("tagging"):
			return "PutBucketTagging"
		case has("versioning"):
			return "PutBucketVersioning"
		case has("website"):
			return "PutBucketWebsite"

		case has("metadataInventoryTable"):
			return "UpdateBucketMetadataInventoryTableConfiguration"
		case has("metadataJournalTable"):
			return "UpdateBucketMetadataJournalTableConfiguration"

		default:
			return "CreateBucket"
		}

	case http.MethodDelete:
		switch {
		case has("cors"):
			return "DeleteBucketCors"
		case has("encryption"):
			return "DeleteBucketEncryption"
		case has("analytics"):
			return "DeleteBucketAnalyticsConfiguration"
		case has("intelligent-tiering"):
			return "DeleteBucketIntelligentTieringConfiguration"
		case has("inventory"):
			return "DeleteBucketInventoryConfiguration"
		case has("lifecycle"):
			return "DeleteBucketLifecycle"
		case has("metadataConfiguration"):
			return "DeleteBucketMetadataConfiguration"
		case has("metadataTable"):
			return "DeleteBucketMetadataTableConfiguration"
		case has("metrics"):
			return "DeleteBucketMetricsConfiguration"
		case has("ownershipControls"):
			return "DeleteBucketOwnershipControls"
		case has("policy"):
			return "DeleteBucketPolicy"
		case has("replication"):
			return "DeleteBucketReplication"
		case has("tagging"):
			return "DeleteBucketTagging"
		case has("website"):
			return "DeleteBucketWebsite"
		case has("publicAccessBlock"):
			return "DeletePublicAccessBlock"
		default:
			return "DeleteBucket"
		}

	case http.MethodPost:
		switch {
		case has("metadataConfiguration"):
			return "CreateBucketMetadataConfiguration"
		case has("metadataTable"):
			return "CreateBucketMetadataTableConfiguration"
		}

	}
	return ""
}

func detectS3ActionKey(method string, q url.Values, hasCopySource bool) string {
	has := func(name string) bool {
		_, ok := q[name]
		return ok
	}

	switch method {
	case http.MethodHead:
		return "HeadObject"

	case http.MethodGet:
		// object GET special queries
		switch {
		case has("acl"):
			return "GetObjectAcl"
		case has("attributes"):
			return "GetObjectAttributes"
		case has("legal-hold"):
			return "GetObjectLegalHold"
		case has("object-lock"):
			return "GetObjectLockConfiguration"
		case has("retention"):
			return "GetObjectRetention"
		case has("tagging"):
			return "GetObjectTagging"
		case has("torrent"):
			return "GetObjectTorrent"
		case has("publicAccessBlock"):
			return "GetPublicAccessBlock"
		case has("select"):
			return "SelectObjectContent"
		case has("restore"):
			return "RestoreObject" // sometimes GET? often POST but map both
		case has("lock"):
			return "GetObjectLockConfiguration"
		case has("uploadId"):
			return "ListParts"
		default:
			return "GetObject"
		}

	case http.MethodPut:

		// Put object subresources
		switch {
		case has("acl"):
			return "PutObjectAcl"
		case has("legal-hold"):
			return "PutObjectLegalHold"
		case has("object-lock"):
			return "PutObjectLockConfiguration"
		case has("retention"):
			return "PutObjectRetention"
		case has("tagging"):
			return "PutObjectTagging"
		case has("publicAccessBlock"):
			return "PutPublicAccessBlock"
		case has("renameObject"):
			return "RenameObject"

		case hasCopySource && has("uploadId"):
			return "UploadPartCopy"
		case has("uploadId"):
			return "UploadPart"
		case hasCopySource:
			return "CopyObject"

		default:
			return "PutObject"
		}

	case http.MethodPost:
		switch {
		case has("restore"):
			return "RestoreObject"
		case has("select"):
			return "SelectObjectContent"
		case has("uploads"):
			return "CreateMultipartUpload"
		case has("uploadId"):
			return "CompleteMultipartUpload"
		case has("delete"):
			return "DeleteObjects"
		}

	case http.MethodDelete:
		switch {
		case has("tagging"):
			return "DeleteObjectTagging"
		case has("uploadId"):
			return "AbortMultipartUpload"
		default:
			return "DeleteObject"
		}
	}

	return ""
}
