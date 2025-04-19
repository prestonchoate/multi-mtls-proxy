package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/prestonchoate/mtlsProxy/internal/db"
	"github.com/prestonchoate/mtlsProxy/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// UserRepository defines the interface for admin user operations
type UserRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.AdminUser, error)
	GetByUsername(ctx context.Context, username string) (*models.AdminUser, error)
	Create(ctx context.Context, user models.AdminUser) error
	Update(ctx context.Context, user models.AdminUser) error
	GetAll(ctx context.Context) (map[uuid.UUID]*models.AdminUser, error)
}

// MongoUserRepository implements UserRepository for MongoDB
type MongoUserRepository struct {
	collection *mongo.Collection
}

// NewMongoUserRepository creates a new MongoDB user repository
func NewMongoUserRepository(client *db.MongoClient, collName string) *MongoUserRepository {
	return &MongoUserRepository{
		collection: client.Collection(collName),
	}
}

// GetByID retrieves a user by ID
func (r *MongoUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AdminUser, error) {
	filter := bson.M{"id": id}
	var user models.AdminUser
	if err := r.collection.FindOne(ctx, filter).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// GetByUsername retrieves a user by username
func (r *MongoUserRepository) GetByUsername(ctx context.Context, username string) (*models.AdminUser, error) {
	filter := bson.M{"userName": username}
	var user models.AdminUser
	if err := r.collection.FindOne(ctx, filter).Decode(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

// Create adds a new user
func (r *MongoUserRepository) Create(ctx context.Context, user models.AdminUser) error {
	// Make sure we have created/updated timestamps
	now := time.Now()
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	user.UpdatedAt = now

	_, err := r.collection.InsertOne(ctx, user)
	return err
}

// Update modifies an existing admin user
func (r *MongoUserRepository) Update(ctx context.Context, user models.AdminUser) error {
	filter := bson.M{"id": user.ID}
	update := bson.M{"$set": user}
	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}

// GetAll retrieves all users as a map
func (r *MongoUserRepository) GetAll(ctx context.Context) (map[uuid.UUID]*models.AdminUser, error) {
	cursor, err := r.collection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	result := make(map[uuid.UUID]*models.AdminUser)
	for cursor.Next(ctx) {
		var user models.AdminUser
		if err := cursor.Decode(&user); err != nil {
			return nil, err
		}
		result[user.ID] = &user
	}

	return result, nil
}
