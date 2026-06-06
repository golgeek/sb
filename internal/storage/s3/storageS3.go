package s3

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/spf13/viper"
)

type StorageS3 struct {
	bucket       string
	region       string
	basePath     string
	emulatorHost string
	sess         *session.Session
}

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

	config := aws.NewConfig()
	if accessKey != "" || secretKey != "" || sessionToken != "" {
		config = config.WithCredentials(credentials.NewStaticCredentials(accessKey, secretKey, sessionToken))
	}
	if region != "" {
		config = config.WithRegion(region)
	}
	if emulatorHost != "" {
		config = config.WithRegion(" ").WithEndpoint(emulatorHost).WithS3ForcePathStyle(true)
	}

	rs.sess, err = session.NewSession(config)
	if err != nil {
		err = fmt.Errorf("unable to open aws.Session: %w", err)
		return
	}

	return
}

func (r *StorageS3) GetFromStorage(key, outputFilePath string) (err error) {
	if r.sess == nil {
		return fmt.Errorf("storage S3 hasn't been initialized")
	}

	file, err := os.OpenFile(outputFilePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return
	}
	defer file.Close()

	ctx := context.Background()

	// Init the s3manager downloader
	uploader := s3manager.NewDownloader(r.sess)

	// Download the file to S3
	_, err = uploader.DownloadWithContext(ctx, file, &s3.GetObjectInput{
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

func (r *StorageS3) PushToStorage(key, inputFilePath string) (err error) {
	if r.sess == nil {
		return fmt.Errorf("storage S3 hasn't been initialized")
	}

	// Open the encrypted file
	file, err := os.Open(inputFilePath)
	if err != nil {
		return
	}
	defer file.Close()

	ctx := context.Background()

	// Init the s3manager uploader
	uploader := s3manager.NewUploader(r.sess)

	// Upload the file to S3
	_, err = uploader.UploadWithContext(ctx, &s3manager.UploadInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(filepath.Join(r.basePath, key)),
		Body:   file,
	})
	if err != nil {
		return fmt.Errorf("unable to upload file to S3: %w", err)
	}

	return
}
