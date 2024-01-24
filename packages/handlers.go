package webapp

import (
	// Includes all packages to be used in this file
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"     // An HTTP router
	//"github.com/joho/godotenv"   // For getting the env variables
	_ "github.com/lib/pq"        // Postgres driver for database/sql, _ indicates it won't be referenced directly in code
	"golang.org/x/crypto/bcrypt" // for hashing passwords
)

// The struct for a task, excluding the user_uuid which is added separately.
// Tasks in JSON will use the JSON tags like "id" instead of "TaskNum".
type Item struct {
	TaskNum int    `json:"id"`
	Task    string `json:"task"`
	Status  bool   `json:"status"`
}

type User struct {
	Email      string    `json:"email"`
	Id         string    `json:"user_id"`
	Name       string    `json:"name"`
	Password   string    `json:"password"`
	TimeStamps time.Time `json:"timestamps"`
}

type Response struct {
	Message    string      `json:"message"`
	StatusCode int         `json:"statusCode"`
	Data       interface{} `json:"data"`
}

type Errors struct {
	StatusCode int         `json:"statusCode"`
	Errors     interface{} `json:"errors"`
}

type LoginResponse struct {
	User        User   `json:"user"`
	AccessToken string `json:"accessToken"`
}

type UserUpdate struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Connect to PostgreSQL database and also retrieve user_id from users table
func OpenConnection() (*sql.DB, string) {
	// Getting constants from .env
	var userId string = ""
	// err := godotenv.Load()
	// if err != nil {
	// 	log.Fatal("Error loading .env file")
	// }

	user := os.Getenv("USER")
	if user == "" {
		log.Fatal("Error loading env variables")
	}
	password := os.Getenv("PASSWORD")
	if password == "" {
		log.Fatal("Error loading env variables")
	}
	dbname := os.Getenv("DB_NAME")
	if dbname == "" {
		log.Fatal("Error loading env variables")
	}

	host := os.Getenv("DB_HOST")
	if host == "" {
		log.Fatal("Error loading env variables")
	}

	dbPortString := os.Getenv("DB_PORT")
	if dbPortString == "" {
		log.Fatal("Error loading env variables")
	}
	dbPort, err := strconv.Atoi(dbPortString)
	if err != nil {
		log.Fatal("Error loading env variables")
	}

	// connecting to database
	// 1. creating the connection string
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=require", host, dbPort, user, password, dbname)

	// 2. validates the arguments provided, doesn't create connection to database
	db, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	// 3. actually opens connection to database
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(os.Stdout, "You have connected to the database successfully")

	return db, userId
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 8)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func CreateResponse(w http.ResponseWriter, r *http.Request, message string, statusCode int, data interface{}) {
	// Create a new instance of Response
	resp := &Response{
		Message:    message,
		StatusCode: statusCode,
		Data:       data,
	}

	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(jsonResp)
}

func CreateError(w http.ResponseWriter, r *http.Request, statusCode int, errors []string) {
	// Create a new instance of Response
	resp := &Errors{
		StatusCode: statusCode,
		Errors:     errors,
	}

	// Marshal the response instance to JSON
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(jsonResp)
}

// create user
var CreateUser = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var newUser User
	var errs []error

	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		switch err {
		case io.EOF:
			errs = append(errs, errors.New("request body is empty"))
		default:
			errs = append(errs, err)
		}
	}

	if newUser.Email == "" {
		errs = append(errs, errors.New("email field is missing"))
	}

	if newUser.Name == "" {
		errs = append(errs, errors.New("name field is missing"))
	}

	if newUser.Password == "" {
		errs = append(errs, errors.New("password field is missing"))
	}

	if len(errs) > 0 {
		CreateResponse(w, r, "Validation failed", http.StatusBadRequest, errs)
		return
	}

	db, _ := OpenConnection()
	defer db.Close()

	hash, hashErr := HashPassword(newUser.Password)
	if hashErr != nil {
		CreateResponse(w, r, "Failed to hash password", http.StatusBadRequest, hashErr)
		return
	}
	newUser.Password = string(hash)

	sqlStatement := `INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING name, email, timestamps, user_id;`
	var updatedUser User
	err = db.QueryRow(sqlStatement, newUser.Name, newUser.Email, newUser.Password).Scan(&updatedUser.Name, &updatedUser.Email, &updatedUser.TimeStamps, &updatedUser.Id)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	CreateResponse(w, r, "Successfully created user", 200, updatedUser)
})

// login user
var LoginUser = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var user User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		switch err {
		case io.EOF:
			CreateResponse(w, r, "request body is empty", http.StatusBadRequest, err)
		default:
			CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		}
		return
	}

	if user.Email == "" || user.Password == "" {
		CreateResponse(w, r, "email or password field is missing", http.StatusBadRequest, err)
		return
	}

	db, _ := OpenConnection()
	defer db.Close()
	sqlStatement := `SELECT name, email, password, user_id, timestamps FROM users WHERE email = $1`
	var storedUser User
	err = db.QueryRow(sqlStatement, user.Email).Scan(&storedUser.Name, &storedUser.Email, &storedUser.Password, &storedUser.Id, &storedUser.TimeStamps)
	if err != nil {
		CreateResponse(w, r, "Invalid credentials", http.StatusBadRequest, err)
		return
	}

	check := CheckPasswordHash(user.Password, storedUser.Password)

	if !check {
		CreateResponse(w, r, "Invalid credentials", http.StatusBadRequest, err)
		return
	}
	storedUser.Password = ""
	jwt, jwtErr := GenerateJWT(storedUser.Id)
	if jwtErr != nil {
		CreateResponse(w, r, jwtErr.Error(), http.StatusBadRequest, err)
		return
	}

	response := LoginResponse{
		User:        storedUser,
		AccessToken: jwt,
	}
	CreateResponse(w, r, "Successfully logged in user", 200, response)
})

var GetUser = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)
	db, _ := OpenConnection()
	defer db.Close()
	sqlStatement := `SELECT name, email, user_id, timestamps FROM users WHERE user_id = $1;`
	var user User
	err := db.QueryRow(sqlStatement, user_id).Scan(&user.Name, &user.Email, &user.Id, &user.TimeStamps)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}
	CreateResponse(w, r, "Successfully fetched user", 200, user)
})

var DeleteUser = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)
	db, _ := OpenConnection()
	defer db.Close()
	sqlStatement := `DELETE FROM users WHERE user_id = $1;`
	_, err := db.Exec(sqlStatement, user_id)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}
	CreateResponse(w, r, "Successfully Deleted user", 200, true)
})

var UpdateUser = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)

	var userUpdate UserUpdate
	err := json.NewDecoder(r.Body).Decode(&userUpdate)
	if err != nil {
		switch err {
		case io.EOF:
			CreateResponse(w, r, "request body is empty", http.StatusBadRequest, err)
		default:
			CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		}
		return
	}

	if userUpdate.Email == "" || userUpdate.Name == "" {
		CreateResponse(w, r, "email or name field is missing", http.StatusBadRequest, err)
		return
	}

	db, _ := OpenConnection()
	defer db.Close()
	var user User
	err = db.QueryRow(`UPDATE users SET email = $1, name = $2 WHERE user_id = $3 RETURNING name, email, user_id, timestamps`, userUpdate.Email, userUpdate.Name, user_id).Scan(&user.Name, &user.Email, &user.Id, &user.TimeStamps)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}
	CreateResponse(w, r, "Successfully logged in user", 200, user)
})

// Get  list of tasks
var GetList = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)

	// Get perPage and pageNumber from the query parameters, provide defaults if they are not provided
	perPage := 10   // Default value
	pageNumber := 1 // Default value
	perPageStr := r.URL.Query().Get("perPage")
	pageNumberStr := r.URL.Query().Get("pageNumber")
	if perPageStr != "" {
		perPage, _ = strconv.Atoi(perPageStr)
	}
	if pageNumberStr != "" {
		pageNumber, _ = strconv.Atoi(pageNumberStr)
	}

	db, _ := OpenConnection()
	// First, count the total number of items
	var totalItems int
	db.QueryRow("SELECT COUNT(*) FROM tasks JOIN users ON tasks.user_uuid = users.user_id WHERE user_id = $1", user_id).Scan(&totalItems)

	// Calculate the total number of pages
	totalPages := int(math.Ceil(float64(totalItems) / float64(perPage)))

	// Get the items for the current page
	rows, err := db.Query(`SELECT id, task, status FROM tasks JOIN users ON tasks.user_uuid = users.user_id WHERE user_id = $1 LIMIT $2 OFFSET $3;`, user_id, perPage, (pageNumber-1)*perPage)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}
	defer rows.Close()
	defer db.Close()

	items := make([]Item, 0)
	for rows.Next() {
		var item Item
		err := rows.Scan(&item.TaskNum, &item.Task, &item.Status)
		if err != nil {
			CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
			return
		}
		items = append(items, item)
	}

	// Calculate the lastPage and nextPage
	lastPage := totalPages
	nextPage := pageNumber + 1
	if nextPage > lastPage {
		nextPage = 0
	}

	// Send the response
	response := map[string]interface{}{
		"perPage":    perPage,
		"pageNumber": pageNumber,
		"lastPage":   lastPage,
		"nextPage":   nextPage,
		"data":       items,
	}
	CreateResponse(w, r, "Successfully fetched all tasks", http.StatusOK, response)
})

var AddTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)
	w.Header().Set("Content-Type", "application/json")
	var newTask Item
	err := json.NewDecoder(r.Body).Decode(&newTask)
	if err != nil {
		switch err {
		case io.EOF:
			CreateResponse(w, r, "request body is empty", http.StatusBadRequest, err)
		default:
			CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		}
		return
	}

	if newTask.Task == "" {
		CreateResponse(w, r, "task field is missing", http.StatusBadRequest, err)
		return
	}
	// wishing a nigga would
	newTask.Status = false

	db, _ := OpenConnection()
	defer db.Close()

	sqlStatement := `INSERT INTO tasks (task, status, user_uuid) VALUES ($1, $2, $3) RETURNING id, task, status;`

	var updatedTask Item
	err = db.QueryRow(sqlStatement, newTask.Task, newTask.Status, user_id).Scan(&updatedTask.TaskNum, &updatedTask.Task, &updatedTask.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		panic(err)
	}
	CreateResponse(w, r, "Successfully created a new task", http.StatusOK, updatedTask)
})

// delete task
var DeleteTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//geting user id from the middleware
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)

	// getting the task id from the request URL
	vars := mux.Vars(r) // vars includes all variables in the request URL route.
	task_id, err := strconv.Atoi(vars["id"])
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	db, _ := OpenConnection()
	sqlStatement := `DELETE FROM tasks WHERE id = $1 AND user_uuid = $2;`

	res, err := db.Exec(sqlStatement, task_id, user_id)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	// verifying if row was deleted
	_, err = res.RowsAffected()
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	CreateResponse(w, r, "Successfully deleted task", http.StatusOK, true)
})

// edit task
var EditTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)

	vars := mux.Vars(r)
	task_id, err := strconv.Atoi(vars["id"])
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}
	var newTask Item
	err = json.NewDecoder(r.Body).Decode(&newTask)
	if err != nil {
		switch err {
		case io.EOF:
			CreateResponse(w, r, "request body is empty", http.StatusBadRequest, err)
		default:
			CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		}
		return
	}

	if newTask.Task == "" {
		CreateResponse(w, r, "task field is missing", http.StatusBadRequest, err)
		return
	}

	db, _ := OpenConnection()
	defer db.Close()

	sqlStatement := `UPDATE tasks SET task = $2 WHERE id = $1 AND user_uuid = $3 RETURNING id, task, status;`
	var updatedTask Item
	err = db.QueryRow(sqlStatement, task_id, newTask.Task, user_id).Scan(&updatedTask.TaskNum, &updatedTask.Task, &updatedTask.Status)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	CreateResponse(w, r, "Successfully edited a task", http.StatusOK, updatedTask)
})

// change task status
var DoneTask = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)
	user_id := claims["user_id"].(string)

	vars := mux.Vars(r)
	task_id, err := strconv.Atoi(vars["id"])
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	// store current status of the task from database
	var currStatus bool

	// store updated task
	var updatedTask Item

	sqlStatement1 := `SELECT status FROM tasks WHERE id = $1 AND user_uuid = $2;`
	sqlStatement2 := `UPDATE tasks SET status = $2 WHERE id = $1 AND user_uuid = $3 RETURNING id, task, status;`

	db, _ := OpenConnection()
	defer db.Close()

	// getting current status of the task
	err = db.QueryRow(sqlStatement1, task_id, user_id).Scan(&currStatus)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	// changing the status of the task
	err = db.QueryRow(sqlStatement2, task_id, !currStatus, user_id).Scan(&updatedTask.TaskNum, &updatedTask.Task, &updatedTask.Status)
	if err != nil {
		CreateResponse(w, r, err.Error(), http.StatusBadRequest, err)
		return
	}

	CreateResponse(w, r, "Successfully updated task status", http.StatusOK, updatedTask)
})
var Hello = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	CreateResponse(w, r, "Server Active", http.StatusOK, true)
})