package webapp

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"context"
)

var SecretKey []byte

func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println(err)
		// log.Fatal("Error loading .env file")
	}

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		log.Fatal("Error loading env variables")
	}
	SecretKey = []byte(secretKey)
}

func GenerateJWT(userId string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["user_id"] = userId
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix() // Set expiration time to 30 minutes from now

	tokenString, err := token.SignedString(SecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}



func JWTAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			CreateResponse(w, r, "Unautheticated", http.StatusUnauthorized, errors.New("token is missing"))
			return
		}

		// Parse the token
		token, err := jwt.Parse(authHeader[len("Bearer "):], func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Return the secret key
			return  SecretKey, nil
		})

		if err != nil {
			CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok && !token.Valid {
			CreateResponse(w, r, "invalid token", http.StatusUnauthorized, err)
			return

		}

		// Save the claims to the context
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))

	})
}
