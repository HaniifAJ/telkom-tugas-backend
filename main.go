package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Database instance and collection
var userCollection *mongo.Collection
var productCollection *mongo.Collection
var ctx context.Context

type Product struct {
	ID        primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Name      string             `json:"name" bson:"name"`
	Price     float64            `json:"price" bson:"price"`
	Rating    float32            `json:"rating" bson:"rating"`
	SoldCount int                `json:"sold" bson:"sold"`
	Location  string             `json:"location" bson:"location"`
	Stock     int                `json:"stock" bson:"stock"`
	Image     string             `json:"image" bson:"image"`
	Grosir    bool               `json:"grosir" bson:"grosir"`
}

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name     string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
	Phone    string             `json:"phone" bson:"phone"`
	Password string             `json:"password" bson:"password"`
}

func hashPassword(password string) string { // O(1)
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func registerHandler(w http.ResponseWriter, r *http.Request) { //O(1)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.Password = hashPassword(user.Password)
	_, err = userCollection.InsertOne(r.Context(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("201 - Successfully Created"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) { //O(1)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.Password = hashPassword(user.Password)
	result := userCollection.FindOne(r.Context(), bson.M{"email": user.Email, "password": user.Password})
	if err := result.Err(); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	var foundUser User
	err = result.Decode(&foundUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user = foundUser

	claims := jwt.StandardClaims{
		Subject:   user.ID.Hex(),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
	//json.NewEncoder(w).Encode(foundUser)
}

// Auth Middleware to check JWT Token
var verifiedUser primitive.ObjectID

func authMiddleware(next http.HandlerFunc) http.HandlerFunc { //O(1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}
		tokenString := strings.ReplaceAll(authHeader, "Bearer ", "")
		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("secret"), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
			userID, err := primitive.ObjectIDFromHex(claims.Subject)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			result := userCollection.FindOne(r.Context(), bson.M{"_id": userID})
			if err := result.Err(); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			verifiedUser = userID
			next(w, r)
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	})
}

// Create an order
func createProduct(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	var product Product
	_ = json.NewDecoder(request.Body).Decode(&product)

	result, err := productCollection.InsertOne(ctx, product)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(result)
}

func getAllProducts(response http.ResponseWriter, request *http.Request) { //O(n)
	response.Header().Set("content-type", "application/json")
	var products []Product
	cursor, err := productCollection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var product Product
		cursor.Decode(&product)
		products = append(products, product)
	}
	if err := cursor.Err(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(products)
}

func searchProductByName(response http.ResponseWriter, request *http.Request) { //O(n)
	response.Header().Set("content-type", "application/json")
	var products []Product
	cursor, err := productCollection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)
	params := mux.Vars(request)
	query := params["query"]
	for cursor.Next(ctx) {
		var product Product
		cursor.Decode(&product)
		if strings.Contains(strings.ToLower(product.Name), strings.ToLower(query)) {
			products = append(products, product)
		}
	}
	if err := cursor.Err(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(products)
}

func getProduct(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var product Product
	err := productCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&product)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(product)
}

// Update an order by ID
func updateProduct(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var product Product
	_ = json.NewDecoder(request.Body).Decode(&product)
	product.ID = id
	result, err := productCollection.ReplaceOne(ctx, bson.M{"_id": id}, product)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(result)
}

func deleteProduct(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	result, err := productCollection.DeleteOne(ctx, bson.M{"_id": id})
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(result)
}

func getMongoClient() (*mongo.Client, error) { //O(1)
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().
		ApplyURI("mongodb+srv://haniif02aj:uQz7VLcY70SoS4JA@test.dkwiku6.mongodb.net/?retryWrites=true&w=majority").
		SetServerAPIOptions(serverAPIOptions)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, fmt.Errorf("error connecting to MongoDB: %s", err)
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error pinging MongoDB: %s", err)
	}
	return client, nil
}

func main() {
	// Set up MongoDB connection
	client, err := getMongoClient()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)
	productCollection = client.Database("tugas-backend").Collection("product")
	userCollection = client.Database("tugas-backend").Collection("user")
	// Set up router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/register", registerHandler).Methods("POST")

	router.HandleFunc("/product", getAllProducts).Methods("GET")
	router.HandleFunc("/product/search/{query}", searchProductByName).Methods("GET")
	router.HandleFunc("/product/{id}", getProduct).Methods("GET")

	router.HandleFunc("/product", authMiddleware(createProduct)).Methods("POST")
	router.HandleFunc("/product/{id}", authMiddleware(updateProduct)).Methods("PUT")
	router.HandleFunc("/product/{id}", authMiddleware(deleteProduct)).Methods("DELETE")

	// Start server
	log.Fatal(http.ListenAndServe(":8080", router))
}
