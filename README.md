# API Test

This API is designed for sending and receiving data and authenticating with JWT. Access to various information has different levels of security protection.

## Setup and Running the API

### Setup Steps:

0. **Install Rust Programming Language**  
   If you haven't installed Rust yet, please do so first.

1. **Create a New Project**  
   Execute the following command to create a new project named `api-test`:
   ```bash
   cargo new api-test
   ```

2. **Edit the `main.rs` File**  
   Navigate to `./src/main.rs` and copy the desired code into it.

3. **Edit the `Cargo.toml` File**  
   Navigate to `./Cargo.toml` and copy the desired code into it.

## Usage Instructions

### 1. Accessing the Root Path

To access the root path, use the following command:
```bash
curl -X GET http://127.0.0.1/
```

### 2. Sending Data with User Token and Access

To send data with a token and user access, use the following command:
```bash
curl -X POST http://127.0.0.1:80/post -H "Authorization: Bearer USER-TOKEN" -H "Content-Type: application/json" -d '{"id": 1, "name": "John", "family": "Doe", "age": 30, "number": 123456}'
```

### 3. Logging In

To log in with the default username and password, use the following command:
```bash
curl -X POST http://127.0.0.1/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "password"}'
```

### 4. Creating a Token for User Role

To create a token for a user role, use the following command:
```bash
curl -X POST http://127.0.0.1:80/create_token -H "Authorization: Bearer ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"username": "any-username-for-user", "role": "user"}'
```

### 5. Getting All Information

To retrieve all information, use the following command:
```bash
curl -X GET http://127.0.0.1:80/data -H "Authorization: Bearer ADMIN-TOKEN"
```

### 6. Getting Information by ID

To retrieve information by ID, use the following command:
```bash
curl -X GET http://127.0.0.1:80/data=<id> -H "Authorization: Bearer ADMIN-TOKEN"
```





## Donations

If you appreciate this project and want to support its development, feel free to send a donation to the following wallet address:

### TON Address 
```
UQA59lyLjF8TXbvAXXyLk9U1f-LN03jyJyit3pXqonZGXZGO
```
### BTC Address
```
bc1q3ltptp54pe587axj5ye26pcqqg3sqrlu9fcam0
```

Your contributions are greatly appreciated!