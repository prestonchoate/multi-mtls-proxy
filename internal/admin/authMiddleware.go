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
			log.Printf("bad header: %v", authHeader)
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		pubKey, err := s.getSigningCert()
		if err != nil {
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
			log.Printf("invalid token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok {
			sub, ok := claims["sub"].(string)
			if !ok {
				log.Printf("admin ID is not valid")
				c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
				c.Abort()
				return
			}

			adminId, err := uuid.Parse(sub)
			if err != nil {
				log.Printf("invalid UUID in sub claim: %v", err)
				c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
				c.Abort()
				return
			}

			admin := s.getAdminById(adminId)
			if admin == nil {
				log.Printf("admin ID %v is not valid", adminId)
				c.JSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
				c.Abort()
				return
			}
			c.Set("admin", admin)
		}

		c.Next()
	}
}
