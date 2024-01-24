package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux" // An HTTP router
	"github.com/joho/godotenv"
	_ "github.com/lib/pq" // Postgres driver for database/sql, _ indicates it won't be referenced directly in code
	"github.com/rs/cors"  // For handling CORS (to be explained)
	"webapp/packages"     // importing files from the packages directory, to be explained
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("Error loading .env file")
	}

	r := mux.NewRouter()
	r.Handle("/", webapp.Hello).Methods("GET")
	r.Handle("/user", webapp.CreateUser).Methods("POST")
	r.Handle("/login", webapp.LoginUser).Methods("POST")
	r.Handle("/user", webapp.JWTAuthMiddleware(webapp.UpdateUser)).Methods("PATCH")
	r.Handle("/user", webapp.JWTAuthMiddleware(webapp.DeleteUser)).Methods("DELETE")
	r.Handle("/user", webapp.JWTAuthMiddleware(webapp.GetUser)).Methods("GET")
	r.Handle("/list", webapp.JWTAuthMiddleware(webapp.GetList)).Methods("GET")
	r.Handle("/list/add", webapp.JWTAuthMiddleware(webapp.AddTask)).Methods("POST")
	r.Handle("/list/delete/{id}", webapp.JWTAuthMiddleware(webapp.DeleteTask)).Methods("DELETE")
	r.Handle("/list/edit/{id}", webapp.JWTAuthMiddleware(webapp.EditTask)).Methods("PUT")
	r.Handle("/list/done/{id}", webapp.JWTAuthMiddleware(webapp.DoneTask)).Methods("PUT")

	// for handling CORS
	c := cors.New(cors.Options{
		// Only add 1 value to allowed origins. Only the first one works. "*" is no exception.
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "DELETE", "POST", "PUT", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Origin", "Accept", "Authorization"},
		AllowCredentials: true,
	})

	// if deployed, looks for port in the environment and runs on it. Otherwise, runs locally on port 8000
	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	// apply the CORS specification on the request, and add relevant CORS headers as necessary
	handler := c.Handler(r)
	log.Println("Listening on port " + port + "...")
	// run on the designated port
	log.Fatal(http.ListenAndServe(":"+port, handler))
}
