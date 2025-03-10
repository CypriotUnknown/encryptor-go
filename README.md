# Go AES Encryption Package

This Go package provides simple and secure AES encryption and decryption functionality. It allows you to encrypt sensitive data and decrypt it back, ensuring confidentiality. The package uses the AES-256 algorithm with a key and initialization vector (IV) for encryption. Using this package, all parties can obtain the same shared secret without transporting it.

There is also a Typescript package available at: https://jsr.io/@cypriot/encryptor:
```bash
npx jsr add @cypriot/encryptor
```

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Generate Keys](#generate-keys)
  - [Compute Secret](#compute-secret)
  - [Encrypt Data](#encrypt-data)
  - [Decrypt Data](#decrypt-data)

## Features

- AES-256 encryption with secure key management.
- Easy-to-use encryption and decryption functions.
- Supports Base64 encoded IVs and encrypted data.
- Error handling for invalid encryption/decryption attempts.

## Installation

To install the package in your Go project, run the following command:

```bash
go get github.com/CypriotUnknown/encryptor-go
```

## Usage

# Generate Keys

To generate keys:

```go
package main

import (
	"encryptor/encryptor"
	"fmt"
)

func main() {
	enc := encryptor.NewEncryptor()

	// Generate key pair
	privateKeyString, publicKeyString, privateKey, err := enc.GenerateKeys()
	if err != nil {
		panic(err)
	}
	fmt.Println("Private Key (PKCS#8, base64):", privateKeyString)
	fmt.Println("Public Key (SPKI, base64):", publicKeyString)
}
```

# Compute Secret

This example assumes you have created keys using the method above on a remote server. After receiving the public key string from the remote server, you can compute the shared secret like so: 

```go
secret, err := enc.ComputeSecret(apiResponse.Data.ServerPublicKey, privateKey)
if err != nil {
    log.Fatalln(err.Error())
}
```

# Encrypt Data

```go
accountInfoDTO := ExampleModel{Hello: "world"}
accountInfoDTOBytes, _ := json.Marshal(accountInfoDTO)
encryptedBody, err := enc.EncryptContent(string(accountInfoDTOBytes), secret)
if err != nil {
    log.Fatalln(err.Error())
}
```

The encryptedBody will be of type:

```go
type EncryptedBody struct {
    IV   string `json:"iv"`   
    Hash string `json:"hash"` 
}
```

# Decrypt Data

To decrypt some data that was encrypted using the above method, you have to pass a type that has an IV and a Hash to the DecryptContent function like so:

```go
decryptedContent, err := enc.DecryptContent(encryptedBody, secret)
if err != nil {
    log.Fatalln(err.Error())
}
```
