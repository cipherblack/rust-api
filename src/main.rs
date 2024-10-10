use actix_web::{web, App, HttpServer, HttpResponse, HttpRequest, ResponseError};
use actix_web::middleware::Logger;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use chrono::{Utc, Duration};
use actix_web::http::header;
use std::fmt;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write; // For writing to a file
use env_logger::Env;
use uuid::Uuid;

// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // User ID (e.g., username)
    exp: usize,  // Expiration time of the token
    jti: String, // Unique identifier for the token (UUID)
    role: String, // User role (e.g., "admin" or "user")
}

// User data structure
#[derive(Serialize, Deserialize, Clone, Debug)]
struct MyData {
    #[serde(default)] // Optional id in deserialization
    id: u32,
    name: String,
    family: String,
    age: u32,
    number: i32,
}

struct AppState {
    data: Mutex<Vec<MyData>>,
    logs: Mutex<HashMap<String, usize>>, // For tracking logs
}

const SECRET_KEY: &[u8] = b"super_secret_key"; // JWT encryption key
const LOG_FILE: &str = "request_logs.txt"; // Log file name

// Define error type
#[derive(Debug)]
enum MyError {
    BadRequest(String),
    Unauthorized,
    Forbidden,
    NotFound(String),
    InternalServerError,
}

// Implement Display for MyError
impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            MyError::BadRequest(ref message) => write!(f, "Invalid Request: {}", message),
            MyError::Unauthorized => write!(f, "Unauthorized: Please provide a valid token."),
            MyError::Forbidden => write!(f, "Forbidden: Access is denied."),
            MyError::NotFound(ref message) => write!(f, "Not Found: {}", message),
            MyError::InternalServerError => write!(f, "Internal Server Error"),
        }
    }
}

impl ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        match *self {
            MyError::BadRequest(ref message) => HttpResponse::BadRequest().body(format!("400 Bad Request: {}", message)),
            MyError::Unauthorized => HttpResponse::Unauthorized().body("401 Unauthorized: Please provide a valid token."),
            MyError::Forbidden => HttpResponse::Forbidden().body("403 Forbidden: Access is denied."),
            MyError::NotFound(ref message) => HttpResponse::NotFound().body(format!("404 Not Found: {}", message)),
            MyError::InternalServerError => HttpResponse::InternalServerError().finish(),
        }
    }
}

// Implement From for String
impl From<String> for MyError {
    fn from(error: String) -> Self {
        MyError::BadRequest(error)
    }
}

// Create JWT
fn create_jwt(username: &str, role: &str) -> Result<String, MyError> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::seconds(3600)) // Token expiration: 1 hour
        .ok_or(MyError::InternalServerError)?
        .timestamp();

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize,
        jti: Uuid::new_v4().to_string(), // Unique identifier for the token (UUID)
        role: role.to_string(), // User role
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET_KEY))
        .map_err(|_| MyError::InternalServerError)
}

// Validate JWT and authenticate
fn validate_jwt(token: &str) -> Result<Claims, MyError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(SECRET_KEY),
        &Validation::new(Algorithm::HS256),
    ).map_err(|_| MyError::Unauthorized)?;

    Ok(token_data.claims)
}

// Function to check token in request header
fn check_auth(req: &HttpRequest) -> Result<String, MyError> {
    // Check query string
    if let Some(query_token) = req.query_string().split("token=").nth(1) {
        return Ok(query_token.to_string());
    }

    // Check Authorization header
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_value) = auth_header.to_str() {
            let token = auth_value.trim_start_matches("Bearer ");
            return Ok(token.to_string());
        }
    }

    Err(MyError::Unauthorized)
}

// Endpoint for login and receiving JWT
async fn login(credentials: web::Json<LoginRequest>, state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    if credentials.username == "admin" && credentials.password == "password" {
        let token = create_jwt(&credentials.username, "admin")?; // Create admin token
        log_request(&state, &req, None).await; // Log to file and console
        Ok(HttpResponse::Ok().json(LoginResponse { token }))
    } else {
        let token = create_jwt(&credentials.username, "user")?; // Create user token
        log_request(&state, &req, None).await; // Log to file and console
        Ok(HttpResponse::Ok().json(LoginResponse { token }))
    }
}

// Login credentials structure
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

// Login response structure
#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

// Index function
async fn index() -> HttpResponse {
    HttpResponse::Ok().body("Welcome to the API!")
}

// Get data
async fn get_data(state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let token = check_auth(&req)?; // Check JWT token
    let claims = validate_jwt(&token)?; // Validate the token

    // Check if the user has permission to access any data
    if !user_has_permission(&claims.role) {
        return Err(MyError::Forbidden); // Return 403 Forbidden if no access
    }
    
    let data = state.data.lock().map_err(|_| MyError::InternalServerError)?; // Lock data
    log_request(&state, &req, None).await; // Log the request
    Ok(HttpResponse::Ok().json(&*data)) // Return all data
}

// Get data by ID
async fn get_data_by_id(state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    let token = check_auth(&req)?; // Check JWT token
    let claims = validate_jwt(&token)?; // Validate the token

    // Check if the user has permission to access this data
    if !user_has_permission(&claims.role) {
        return Err(MyError::Forbidden); // Return 403 Forbidden if no access
    }

    let id: u32 = req.match_info().get("id").unwrap_or("0").parse().unwrap_or(0); // Get ID from request
    let data = state.data.lock().map_err(|_| MyError::InternalServerError)?; // Lock data

    // Find the requested data
    if let Some(item) = data.iter().find(|item| item.id == id) {
        log_request(&state, &req, Some(item.clone())).await; // Log the request
        Ok(HttpResponse::Ok().json(item)) // Return the requested item
    } else {
        Err(MyError::NotFound(format!("Data with id {} not found", id))) // Return NotFound error
    }
}


// Post new data
async fn post_data(item: web::Json<MyData>, state: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, MyError> {
    // Check JWT token and validate it
    let token = check_auth(&req)?; // Check JWT token
    let claims = validate_jwt(&token)?; // Validate the token

    // Check if the user's role is 'user'
    if claims.role != "user" {
        return Err(MyError::Forbidden); // Return 403 Forbidden if the role is not 'user'
    }

    let new_item = item.clone(); // Clone the item for later use
    let mut data = state.data.lock().map_err(|_| MyError::InternalServerError)?; // Lock data
    data.push(new_item); // Add new item
    log_request(&state, &req, Some(item.clone())).await; // Log to file only

    // Return a response with the message "ok بود"
    Ok(HttpResponse::Created().json("200 OK")) // Return Created status with message
}


// Get client IP address
fn get_client_ip(req: &HttpRequest) -> String {
    // First check for the X-Forwarded-For header
    if let Some(forwarded_for) = req.headers().get("X-Forwarded-For") {
        if let Ok(ip) = forwarded_for.to_str() {
            return ip.split(',').next().unwrap_or("Unknown").to_string(); // Return the first IP address
        }
    }
    // Use the connection info to get the IP address
    req.connection_info().peer_addr()
    .and_then(|addr| addr.split(':').next()) // Extract the IP part before the colon
    .unwrap_or("Unknown")
    .to_string()
}


// Log request information
async fn log_request(state: &web::Data<AppState>, req: &HttpRequest, item: Option<MyData>) {
    let ip = get_client_ip(req);
    let method = req.method();
    let uri = req.uri();
    let headers = format!("{:?}", req.headers());
    let log_entry = format!(
        "IP: {}, Method: {}, URI: {}, Headers: {}, Data: {:?}\n",
        ip, method, uri, headers, item
    );
    
    // Write log entry to file
    let mut logs = state.logs.lock().unwrap();
    *logs.entry(ip.clone()).or_insert(0) += 1; // Track number of requests
    
    // Open the file and write the log
    if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(LOG_FILE) {
        if let Err(e) = writeln!(file, "{}", log_entry) {
            eprintln!("Failed to write log entry: {:?}", e); // Print error if write fails
        }
    } else {
        eprintln!("Failed to open log file for writing.");
    }
}


// Check user permissions based on role
fn user_has_permission(role: &str) -> bool {
    role == "admin" // Only admin has access to create tokens
}

// Create token with specified role
async fn create_token_with_role(req: web::Json<TokenRequest>, state: web::Data<AppState>, http_req: HttpRequest) -> Result<HttpResponse, MyError> {
    // Check the current user's token to see if they have admin permissions
    let current_token = check_auth(&http_req)?;
    let claims = validate_jwt(&current_token)?; // Validate the current token

    // Only allow admin users to create new tokens
    if claims.role != "admin" {
        return Err(MyError::Forbidden); // Return Forbidden error if not admin
    }

    if req.role != "admin" && req.role != "user" {
        return Err(MyError::BadRequest("Role must be either 'admin' or 'user'".to_string()));
    }

    let token = create_jwt(&req.username, &req.role)?;
    log_request(&state, &http_req, None).await; // Log the request

    Ok(HttpResponse::Ok().json(TokenResponse { token }))
}

#[derive(Deserialize)]
struct TokenRequest {
    username: String,
    role: String,
}

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

// Main function
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("info")); // Initialize logger
    let data = Mutex::new(vec![]); // Initialize data
    let logs = Mutex::new(HashMap::new()); // Initialize logs
    let state = web::Data::new(AppState { data, logs });

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(Logger::default()) // Add logger middleware
            .route("/", web::get().to(index)) // Added index function here
            .route("/login", web::post().to(login))
            .route("/data", web::get().to(get_data))
            .route("/data={id}", web::get().to(get_data_by_id))
            .route("/post", web::post().to(post_data))
            .route("/create_token", web::post().to(create_token_with_role))
    })
    .bind("127.0.0.1:80")?
    .run()
    .await
}
