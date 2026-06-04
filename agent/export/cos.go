package export

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kyanos/common"

	"github.com/tencentyun/cos-go-sdk-v5"
)

// COSUploader handles file uploads to Tencent Cloud Object Storage (COS)
// using the official SDK. It supports key credentials or reading them
// from standard Tencent Cloud environment variables.
type COSUploader struct {
	client    *cos.Client
	bucket    string
	region    string
	prefix    string
	deleteRaw bool // If true, delete local file upon successful upload
}

// COSUploaderConfig tunes credentials and target details for COS.
type COSUploaderConfig struct {
	SecretID  string
	SecretKey string
	Bucket    string
	Region    string
	Prefix    string
	DeleteRaw bool
}

// NewCOSUploader initializes a new uploader. If SecretID/SecretKey are empty,
// it attempts to read them from TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY env vars.
func NewCOSUploader(cfg COSUploaderConfig) (*COSUploader, error) {
	secretID := cfg.SecretID
	secretKey := cfg.SecretKey

	if secretID == "" {
		secretID = os.Getenv("TENCENTCLOUD_SECRET_ID")
	}
	if secretKey == "" {
		secretKey = os.Getenv("TENCENTCLOUD_SECRET_KEY")
	}

	if secretID == "" || secretKey == "" {
		return nil, fmt.Errorf("missing Tencent Cloud credentials: SecretID and SecretKey are required")
	}
	if cfg.Bucket == "" || cfg.Region == "" {
		return nil, fmt.Errorf("bucket and region are required for COS upload")
	}

	// Normalize bucket and region
	bucket := cfg.Bucket
	region := cfg.Region

	// BaseURL URL parsing
	rawURL := fmt.Sprintf("https://%s.cos.%s.myqcloud.com", bucket, region)
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid COS URL %q: %w", rawURL, err)
	}

	client := cos.NewClient(&cos.BaseURL{BucketURL: u}, &http.Client{
		Timeout: 30 * time.Second,
		Transport: &cos.AuthorizationTransport{
			SecretID:  secretID,
			SecretKey: secretKey,
		},
	})

	return &COSUploader{
		client:    client,
		bucket:    bucket,
		region:    region,
		prefix:    strings.Trim(cfg.Prefix, "/"),
		deleteRaw: cfg.DeleteRaw,
	}, nil
}

// Upload uploads the local file to COS.
// The remote object key is constructed as: <prefix>/<filename>
func (u *COSUploader) Upload(ctx context.Context, localPath string) (string, error) {
	if _, err := os.Stat(localPath); err != nil {
		return "", fmt.Errorf("local file not found %q: %w", localPath, err)
	}

	filename := filepath.Base(localPath)
	var key string
	if u.prefix != "" {
		key = u.prefix + "/" + filename
	} else {
		key = filename
	}

	common.AgentLog.Infof("COS: starting upload %q to bucket %q as object %q", localPath, u.bucket, key)

	_, err := u.client.Object.PutFromFile(ctx, key, localPath, nil)
	if err != nil {
		return "", fmt.Errorf("COS put object %q failed: %w", key, err)
	}

	cosURL := fmt.Sprintf("https://%s.cos.%s.myqcloud.com/%s", u.bucket, u.region, key)
	common.AgentLog.Infof("COS: upload successful. URL: %s", cosURL)

	// Clean up local file if requested
	if u.deleteRaw {
		if err := os.Remove(localPath); err != nil {
			common.AgentLog.Warnf("COS: failed to delete local raw file %q after upload: %v", localPath, err)
		} else {
			common.AgentLog.Infof("COS: cleaned up local raw file %q", localPath)
		}
	}

	return cosURL, nil
}
