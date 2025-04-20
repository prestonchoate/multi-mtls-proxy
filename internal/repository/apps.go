package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/prestonchoate/mtlsProxy/internal/db"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// AppRepository defines the interface for app config operations
type AppRepository interface {
	GetAll(ctx context.Context, ownerId uuid.UUID) (map[string]models.AppConfig, error)
	GetByID(ctx context.Context, appId string) (*models.AppConfig, error)
	Create(ctx context.Context, app models.AppConfig) error
	Update(ctx context.Context, app models.AppConfig) error
	Delete(ctx context.Context, appId string) error
	Upsert(ctx context.Context, app models.AppConfig) error
}

// MongoAppRepository implements AppRepository for MongoDB storage
type MongoAppRepository struct {
	collection *mongo.Collection
}

// NewMongoAppRepository creates a new instance of MongoAppRepository
func NewMongoAppRepository(client *db.MongoClient, collName string) *MongoAppRepository {
	return &MongoAppRepository{
		collection: client.Collection(collName),
	}
}

// GetAll retrieves all apps owned by the specified user
func (r *MongoAppRepository) GetAll(ctx context.Context, ownerID uuid.UUID) (map[string]models.AppConfig, error) {
	filter := bson.M{"owner": ownerID}
	cursor, err := r.collection.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	result := make(map[string]models.AppConfig)
	for cursor.Next(ctx) {
		var app models.AppConfig
		if err := cursor.Decode(&app); err != nil {
			return nil, err
		}
		result[app.AppID] = app
	}

	return result, nil
}

// GetByID retrieves an app by its appID
func (r *MongoAppRepository) GetByID(ctx context.Context, appID string) (*models.AppConfig, error) {
	filter := bson.M{"appId": appID}
	var app models.AppConfig
	if err := r.collection.FindOne(ctx, filter).Decode(&app); err != nil {
		return nil, err
	}
	return &app, nil
}

// Create adds a new app config
func (r *MongoAppRepository) Create(ctx context.Context, app models.AppConfig) error {
	_, err := r.collection.InsertOne(ctx, app)
	return err
}

// Update modifies an existing app config
func (r *MongoAppRepository) Update(ctx context.Context, app models.AppConfig) error {
	filter := bson.M{"appId": app.AppID}
	update := bson.M{"$set": app}
	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// Upsert either modifies an existing app config or creates a new one if it does not exist
func (r *MongoAppRepository) Upsert(ctx context.Context, app models.AppConfig) error {
	app.UpdatedAt = time.Now()
	filter := bson.M{"appId": app.AppID}
	update := bson.M{"$set": app}
	opts := options.Update().SetUpsert(true)
	_, err := r.collection.UpdateOne(ctx, filter, update, opts)

	return err
}

// Delete removes an app config
func (r *MongoAppRepository) Delete(ctx context.Context, appID string) error {
	filter := bson.M{"appId": appID}
	_, err := r.collection.DeleteOne(ctx, filter)
	return err
}
