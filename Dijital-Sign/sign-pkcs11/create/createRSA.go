package create

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/miekg/pkcs11"
)

// KeyPairResponse represents the structure for the RSA key pair response
type KeyPairResponse struct {
	PublicKeyLabel   string              `json:"public_key_label"`
	PrivateKeyLabel  string              `json:"private_key_label"`
	PublicKeyHandle  pkcs11.ObjectHandle `json:"public_key_handle"`
	PrivateKeyHandle pkcs11.ObjectHandle `json:"private_key_handle"`
}

// GenerateRSAKey generates an RSA key pair on the HSM and returns the details in JSON format
func GenerateRSAKey(slotID int, userPin string, keySize int, keyLabel string) (string, error) {
	// Get the PKCS#11 library path from the environment
	libraryPath := os.Getenv("PKCS11_LIB")
	if libraryPath == "" {
		return "", fmt.Errorf("PKCS11_LIB environment variable is not set")
	}

	// Initialize PKCS#11 library
	p := pkcs11.New(libraryPath)
	if err := p.Initialize(); err != nil {
		return "", fmt.Errorf("failed to initialize PKCS#11 library: %v", err)
	}
	defer p.Finalize()

	// Open a session for the given slot ID
	session, err := p.OpenSession(uint(slotID), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return "", fmt.Errorf("failed to open session: %v", err)
	}
	defer p.CloseSession(session)

	// Log in to the session using the user PIN
	if err := p.Login(session, pkcs11.CKU_USER, userPin); err != nil {
		return "", fmt.Errorf("failed to log in: %v", err)
	}
	defer p.Logout(session)

	// Define key attributes
	modulusBits := keySize
	keyID := []byte{1, 2, 3, 4}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_pub"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, modulusBits),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
	}

	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel+"_priv"),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
    	pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}

	// Generate the RSA key pair
	pubKeyHandle, privKeyHandle, err := p.GenerateKeyPair(
		session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		publicKeyTemplate,
		privateKeyTemplate,
	)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key pair: %v", err)
	}

	// Create the response struct
	response := KeyPairResponse{
		PublicKeyLabel:   keyLabel + "_pub",
		PrivateKeyLabel:  keyLabel + "_priv",
		PublicKeyHandle:  pubKeyHandle,
		PrivateKeyHandle: privKeyHandle,
	}

	// Convert the response to JSON format
	jsonResponse, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to generate JSON response: %v", err)
	}

	return string(jsonResponse), nil
}
