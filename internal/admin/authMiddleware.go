package admin

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (s *Server) validateAdminAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			log.Println("Auth header is missing or invalid")
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		pubKey, err := s.getSigningCert()
		if err != nil {
			log.Printf("Failed to load signing cert: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"message": "internal error"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
			return pubKey, nil
		},
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
			jwt.WithIssuer("mtls-proxy-admin"),
			jwt.WithAudience("admin"),
		)

		if err != nil || !token.Valid {
			log.Println("invalid token")
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok {
			sub, ok := claims["sub"].(string)
			if !ok {
				log.Println("admin ID is not valid in token claims")
				c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
				c.Abort()
				return
			}

			adminId, err := uuid.Parse(sub)
			if err != nil {
				log.Println("invalid UUID in sub claim")
				c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
				c.Abort()
				return
			}

			admin := s.getAdminById(adminId)
			if admin == nil {
				log.Println("admin ID is not valid")
				c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
				c.Abort()
				return
			}
			c.Set("admin", admin)
		}

		c.Next()
	}
}
