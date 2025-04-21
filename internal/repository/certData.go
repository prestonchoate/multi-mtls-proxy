package repository

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/prestonchoate/mtlsProxy/internal/cryptohelper"
	"github.com/prestonchoate/mtlsProxy/internal/db"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Repository interface for certificate storage
type CertificateRepository interface {
	SaveCert(ctx context.Context, name string, certData []byte) error
	SaveKey(ctx context.Context, name string, keyData []byte) error
	GetCert(ctx context.Context, name string) ([]byte, error)
	GetKey(ctx context.Context, name string) ([]byte, error)
	DeleteCert(ctx context.Context, name string) error
	DeleteKey(ctx context.Context, name string) error
}

type MongoCertificateRepository struct {
	client         *db.MongoClient
	collectionName string
	encKy          string
}

func NewMongoCertificateRepository(client *db.MongoClient, collectionName string, encryptionKey string) *MongoCertificateRepository {
	keyBytes := []byte(encryptionKey)
	if !cryptohelper.ValidateKey(keyBytes) {
		log.Fatalf("Encryption key must be 16, 24, or 32 bytes, got %d", len(keyBytes))
	}

	return &MongoCertificateRepository{
		client:         client,
		collectionName: collectionName,
		encKy:          encryptionKey,
	}
}

// SaveCert encrypts and writes cert data to DB
func (r *MongoCertificateRepository) SaveCert(ctx context.Context, name string, certData []byte) error {
	encryptedData, err := cryptohelper.Encrypt(certData, []byte(r.encKy))
	if err != nil {
		return err
	}

	return r.writeRecord(ctx, name, []byte(encryptedData), models.Cert)
}

// SaveKey encrypts and writes key to DB
func (r *MongoCertificateRepository) SaveKey(ctx context.Context, name string, keyData []byte) error {
	encryptedData, err := cryptohelper.Encrypt(keyData, []byte(r.encKy))
	if err != nil {
		return err
	}

	return r.writeRecord(ctx, name, []byte(encryptedData), models.Key)
}

// writeRecord holds the logic to persist any cert or key to DB
func (r *MongoCertificateRepository) writeRecord(ctx context.Context, name string, data []byte, recordType models.CertDataType) error {
	if r.collectionName == "" {
		return fmt.Errorf("collection name: \"%s\" invalid", r.collectionName)
	}

	now := time.Now()

	certDataRecord := models.CertData{
		Name:      name,
		Type:      recordType,
		Data:      string(data),
		UpdatedAt: now,
	}

	update := bson.M{
		"$set": certDataRecord,
		"$setOnInsert": bson.M{
			"createdAt": now,
		},
	}

	coll := r.client.Database.Collection(r.collectionName)
	filter := bson.M{"name": certDataRecord.Name, "type": recordType}
	opts := options.Update()
	_, err := coll.UpdateOne(ctx, filter, update, opts)

	return err
}

// GetCert retrieves and decrypts cert from DB
func (r *MongoCertificateRepository) GetCert(ctx context.Context, name string) ([]byte, error) {
	return r.getRecord(ctx, name, models.Cert)
}

// GetKey retrieves and decrypts key from DB
func (r *MongoCertificateRepository) GetKey(ctx context.Context, name string) ([]byte, error) {
	return r.getRecord(ctx, name, models.Key)
}

// getRecord holds the logic to retrieve any cert or key from the DB
func (r *MongoCertificateRepository) getRecord(ctx context.Context, name string, recordType models.CertDataType) ([]byte, error) {
	coll := r.client.Database.Collection(r.collectionName)
	filter := bson.M{"name": name, "type": recordType}
	var certRecord models.CertData
	err := coll.FindOne(ctx, filter).Decode(&certRecord)
	if err != nil {
		return nil, err
	}

	return cryptohelper.Decrypt(certRecord.Data, []byte(r.encKy))
}

// DeleteCert removes cert record from DB
func (r *MongoCertificateRepository) DeleteCert(ctx context.Context, name string) error {
	coll := r.client.Database.Collection(r.collectionName)
	filter := bson.M{"name": name, "type": models.Cert}
	_, err := coll.DeleteOne(ctx, filter)
	return err
}

// DeleteKey removes key record from DB
func (r *MongoCertificateRepository) DeleteKey(ctx context.Context, name string) error {
	coll := r.client.Database.Collection(r.collectionName)
	filter := bson.M{"name": name, "type": models.Key}
	_, err := coll.DeleteOne(ctx, filter)
	return err
}
