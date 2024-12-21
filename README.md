# README

## Overview

This project is a Go-based web application utilizing the Gin framework. It interacts with PKCS#11 libraries for RSA key management, signing, verification, and includes a simple blockchain implementation for securely adding and retrieving data blocks. The application exposes several REST API endpoints for these functionalities.

## Prerequisites

Before running the application, ensure the following dependencies are installed and configured:

1. **Go:** Version 1.18 or higher.
2. **Gin Framework:** Installed via `go get github.com/gin-gonic/gin`.
3. **PKCS#11 Library:** Ensure the required library (`/lib64/libprocryptoki.so`) is available for RSA operations.
4. **Additional Modules:**
   - `create` for RSA key creation.
   - `signature` for signing and verifying data.
   - `blockchain` for managing blockchain operations.
5. **Port Configuration:** Ensure port `8080` is available on your system.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd /go-pkcs11
   ```
2. Install dependencies:
   ```bash
   go mod tidy
   ```
3. Build the project:
   ```bash
   go build -o main
   ```

## Running the Application

To start the server, execute the following command:
```bash
./main
```
The application will be available at `http://localhost:8080`.

## API Endpoints

### Blockchain Endpoints

#### Add a New Block
**POST** `/BlockChain/Add`
- **Request Body:**
  ```json
  {
    "Data": "<string>",
    "Signature": "<string>"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Yeni blok eklendi."
  }
  ```

#### List All Blocks
**GET** `/BlockChain/List`
- **Response:**
  ```json
  [
    {
      "Data": "<string>",
      "Signature": "<string>"
    }
  ]
  ```

### RSA Endpoints

#### Generate an RSA Key
**POST** `/create/rsaCreate`
- **Request Body:**
  ```json
  {
    "SlotId": <int>,
    "UserPin": "<string>",
    "KeySize": <int>,
    "KeyLabel": "<string>"
  }
  ```
- **Response:**
  ```json
  {
    "message": "RSA Key created successfully."
  }
  ```

#### Sign Text with RSA
**POST** `/RSA/Text/Signature`
- **Request Body:**
  ```json
  {
    "SlotId": <int>,
    "UserPin": "<string>",
    "KeyLabel": "<string>",
    "Signauture": "<string>"
  }
  ```
- **Response:**
  ```json
  {
    "message": "<signature>"
  }
  ```

#### Verify RSA Signature
**POST** `/RSA/Text/Verifty`
- **Request Body:**
  ```json
  {
    "SlotId": <int>,
    "UserPin": "<string>",
    "KeyLabel": "<string>",
    "Signauture": "<string>",
    "SignautureHex": "<string>"
  }
  ```
- **Response:**
  ```json
  {
    "message": "Verification successful."
  }
  ```

## Project Structure

- **`main.go`**: Entry point of the application.
- **`create`**: Module for RSA key generation.
- **`signature`**: Module for signing and verifying data.
- **`blockchain`**: Simple blockchain implementation for secure data storage.

## Future Work

- Add support for EC key generation and operations.
- Enhance blockchain functionalities with real-world use cases.
- Add comprehensive error handling and logging.



