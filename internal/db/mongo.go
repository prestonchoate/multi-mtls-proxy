package db

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/prestonchoate/mtlsProxy/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type MongoClient struct {
	Client   *mongo.Client
	Database *mongo.Database
}

func NewMongoClient(uri, dbName string) (*MongoClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(fmt.Sprintf("%s/%s", uri, dbName))
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err = client.Ping(ctx, readpref.Primary()); err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %w", err)
	}

	log.Println("Mongo Connection successful")
	database := client.Database(dbName)

	return &MongoClient{
		Client:   client,
		Database: database,
	}, nil
}

// Close disconnects from DB
func (m *MongoClient) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.Client.Disconnect(ctx)
}

// Collection returns a handle to a specified collection
func (m *MongoClient) Collection(name string) *mongo.Collection {
	return m.Database.Collection(name)
}

// Make sure indexes are set up on collections
func EnsureIndexes(client *MongoClient, cfg *models.Config) error {
	ctx := context.Background()

	// Create unique index on appId for apps collection
	appModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "appId", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	if _, err := client.Collection(cfg.MongoAppsColl).Indexes().CreateOne(ctx, appModel); err != nil {
		return err
	}

	// Create unique index on userName for users collection
	userModel := mongo.IndexModel{
		Keys:    bson.D{{Key: "userName", Value: 1}},
		Options: options.Index().SetUnique(true),
	}

	if _, err := client.Collection(cfg.MongoUsersColl).Indexes().CreateOne(ctx, userModel); err != nil {
		return err
	}

	// Create index on owner for apps collection for efficient filtering
	ownerModel := mongo.IndexModel{
		Keys: bson.D{{Key: "owner", Value: 1}},
	}
	if _, err := client.Collection(cfg.MongoAppsColl).Indexes().CreateOne(ctx, ownerModel); err != nil {
		return err
	}

	return nil
}
