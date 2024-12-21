package signature

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"

    pkcs11 "github.com/miekg/pkcs11"
)

func RSASignStr(slotID int, pin string, keyLabel string, Signauture string) (string, error) {
    libraryPath := os.Getenv("PKCS11_LIB")

    p := pkcs11.New(libraryPath)
    if p == nil {
        return "", fmt.Errorf("PKCS#11 kütüphanesi yüklenemedi")
    }

    err := p.Initialize()
    if err != nil {
        return "", fmt.Errorf("Initialize hatası: %v", err)
    }
    defer p.Finalize()

    session, err := p.OpenSession(uint(slotID), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
        return "", fmt.Errorf("OpenSession hatası: %v", err)
    }
    defer p.CloseSession(session)

    err = p.Login(session, pkcs11.CKU_USER, pin)
    if err != nil {
        return "", fmt.Errorf("Login hatası: %v", err)
    }
    defer p.Logout(session)

    // Özel anahtarı bul
    template := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
    }

    err = p.FindObjectsInit(session, template)
    if err != nil {
        return "", fmt.Errorf("FindObjectsInit hatası: %v", err)
    }

    objs, _, err := p.FindObjects(session, 1)
    if err != nil {
        p.FindObjectsFinal(session)
        return "", fmt.Errorf("FindObjects hatası: %v", err)
    }

    err = p.FindObjectsFinal(session)
    if err != nil {
        return "", fmt.Errorf("FindObjectsFinal hatası: %v", err)
    }

    if len(objs) == 0 {
        return "", fmt.Errorf("Belirtilen label ile anahtar bulunamadı")
    }

    keyHandle := objs[0]

    // Mesajı imzala
    message := []byte(Signauture)
    hash := sha256.Sum256(message)

    digestInfoPrefix := []byte{
        0x30, 0x31, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    }

    dataToSign := append(digestInfoPrefix, hash[:]...)

    err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, keyHandle)
    if err != nil {
        return "", fmt.Errorf("SignInit hatası: %v", err)
    }

    signature, err := p.Sign(session, dataToSign)
    if err != nil {
        return "", fmt.Errorf("Sign hatası: %v", err)
    }

    // İmzayı hex formatında döndür
    return hex.EncodeToString(signature), nil
}

// func main() {
//     sig, err := RSASignStr(0, "1111", "RSAKey3_priv", "Hello World")
//     if err != nil {
//         fmt.Printf("İmzalama hatası: %v\n", err)
//         os.Exit(1)
//     }

//     fmt.Printf("Oluşturulan İmza (hex): %s\n", sig)
// }
