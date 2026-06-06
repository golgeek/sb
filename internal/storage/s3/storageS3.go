package s3

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/viper"
)

// StorageS3 stores and retrieves objects in an S3 bucket using aws-sdk-go-v2.
// All keys are stored under basePath within the bucket.
type StorageS3 struct {
	bucket       string
	region       string
	basePath     string
	emulatorHost string
	client       *s3.Client
}

// NewStorageS3 builds an S3-backed storage from the given Viper options. It
// reads the bucket, region, keys-base-path, emulator-host and the optional
// static AWS credentials (aws-access-key/aws-secret-key/aws-session-token).
//
// When emulator-host is set, the client is pointed at that endpoint using
// path-style addressing; this is used both for S3-compatible emulators and by
// the unit tests. It returns an error if the required bucket/region are missing
// or if the AWS configuration cannot be loaded.
func NewStorageS3(options *viper.Viper) (rs *StorageS3, err error) {

	bucket := options.GetString("bucket")
	region := options.GetString("region")
	basePath := options.GetString("keys-base-path")
	emulatorHost := options.GetString("emulator-host")
	accessKey := options.GetString("aws-access-key")
	secretKey := options.GetString("aws-secret-key")
	sessionToken := options.GetString("aws-session-token")

	if bucket == "" || region == "" {
		err = fmt.Errorf("s3.bucket and s3.region options can't be empty")
		return
	}

	rs = &StorageS3{
		bucket:       bucket,
		region:       region,
		basePath:     basePath,
		emulatorHost: emulatorHost,
	}

	// Assemble the base configuration: the region, plus static credentials when
	// any of them is provided (otherwise the SDK's default credential chain is
	// used).
	loadOptions := []func(*config.LoadOptions) error{
		config.WithRegion(region),
	}
	if accessKey != "" || secretKey != "" || sessionToken != "" {
		loadOptions = append(loadOptions, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		))
	}

	cfg, err := config.LoadDefaultConfig(context.Background(), loadOptions...)
	if err != nil {
		err = fmt.Errorf("unable to load AWS configuration: %w", err)
		return
	}

	// Build the S3 client. When talking to an emulator endpoint, force
	// path-style addressing and only calculate request checksums when the API
	// requires them, since emulators commonly do not support the trailing
	// checksum (aws-chunked) encoding the SDK would otherwise add to uploads.
	rs.client = s3.NewFromConfig(cfg, func(o *s3.Options) {
		if emulatorHost != "" {
			o.BaseEndpoint = aws.String(emulatorHost)
			o.UsePathStyle = true
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		}
	})

	return
}

// GetFromStorage downloads the object stored under key (within basePath) into
// outputFilePath, creating or truncating that file. It returns an error if the
// storage was not initialized or if the download or flush fails.
func (r *StorageS3) GetFromStorage(key, outputFilePath string) (err error) {
	if r.client == nil {
		return fmt.Errorf("storage S3 hasn't been initialized")
	}

	file, err := os.OpenFile(outputFilePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return
	}
	defer file.Close()

	// The download manager fetches the object (potentially in parallel ranged
	// parts) and writes it to the file via its io.WriterAt interface.
	downloader := manager.NewDownloader(r.client)
	_, err = downloader.Download(context.Background(), file, &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(filepath.Join(r.basePath, key)),
	})
	if err != nil {
		return fmt.Errorf("unable to download file %s from S3: %w", filepath.Join(r.basePath, key), err)
	}

	err = file.Sync()
	if err != nil {
		return fmt.Errorf("unable to sync the output file after downloading from S3: %w", err)
	}

	return
}

// PushToStorage uploads inputFilePath to the object stored under key (within
// basePath). It returns an error if the storage was not initialized or if the
// upload fails.
func (r *StorageS3) PushToStorage(key, inputFilePath string) (err error) {
	if r.client == nil {
		return fmt.Errorf("storage S3 hasn't been initialized")
	}

	// Open the (encrypted) file to upload.
	file, err := os.Open(inputFilePath)
	if err != nil {
		return
	}
	defer file.Close()

	// The upload manager streams the file to S3, switching to a multipart
	// upload automatically for large objects.
	uploader := manager.NewUploader(r.client)
	_, err = uploader.Upload(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(filepath.Join(r.basePath, key)),
		Body:   file,
	})
	if err != nil {
		return fmt.Errorf("unable to upload file to S3: %w", err)
	}

	return
}
