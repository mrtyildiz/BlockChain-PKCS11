package main

import (
    "crypto/sha256"
    "fmt"
    "os"

    pkcs11 "github.com/miekg/pkcs11"
)

func main() {
    // PKCS#11 kütüphanesinin yolu (Kendi HSM kütüphanenizi belirtin)
    libPath := "/lib64/libprocryptoki.so"
    // Slot ID (HSM üzerindeki slot id genelde önceden bilinir)
    slotID := uint(0)
    // HSM kullanıcı PIN'i
    pin := "1111"
    // İmzalama yapacağımız özel RSA anahtarın label değeri
    keyLabel := "RSAKey3_priv"

    // PKCS#11 context oluştur
    p := pkcs11.New(libPath)
    if p == nil {
        fmt.Println("PKCS#11 kütüphanesi yüklenemedi.")
        os.Exit(1)
    }

    err := p.Initialize()
    if err != nil {
        fmt.Printf("Initialize hatası: %v\n", err)
        os.Exit(1)
    }
    defer p.Finalize()

    session, err := p.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
    if err != nil {
        fmt.Printf("OpenSession hatası: %v\n", err)
        os.Exit(1)
    }
    defer p.CloseSession(session)

    err = p.Login(session, pkcs11.CKU_USER, pin)
    if err != nil {
        fmt.Printf("Login hatası: %v\n", err)
        os.Exit(1)
    }
    defer p.Logout(session)

    // Özel anahtarı bul
    template := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
    }

    err = p.FindObjectsInit(session, template)
    if err != nil {
        fmt.Printf("FindObjectsInit hatası: %v\n", err)
        os.Exit(1)
    }

    objs, _, err := p.FindObjects(session, 1)
    if err != nil {
        fmt.Printf("FindObjects hatası: %v\n", err)
        os.Exit(1)
    }

    err = p.FindObjectsFinal(session)
    if err != nil {
        fmt.Printf("FindObjectsFinal hatası: %v\n", err)
        os.Exit(1)
    }

    if len(objs) == 0 {
        fmt.Println("Belirtilen label ile anahtar bulunamadı")
        os.Exit(1)
    }

    keyHandle := objs[0]

    // İmzalanacak veri
    message := []byte("Hello World")
    hash := sha256.Sum256(message)

    // SHA-256 için PKCS#1 v1.5 DigestInfo yapısı (RFC 3447, Appendix B.1)
    // SHA256 OID = 2.16.840.1.101.3.4.2.1
    // DER-encoded prefix:
    // 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 (SHA-256 DigestInfo prefix)
    digestInfoPrefix := []byte{
        0x30, 0x31, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    }

    dataToSign := append(digestInfoPrefix, hash[:]...)

    // İmza işlemini başlat (CKM_RSA_PKCS PKCS#1 v1.5 şemasına göre imzalar)
    err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, keyHandle)
    if err != nil {
        fmt.Printf("SignInit hatası: %v\n", err)
        os.Exit(1)
    }

    signature, err := p.Sign(session, dataToSign)
    if err != nil {
        fmt.Printf("Sign hatası: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("İmzalanan mesaj: %s\n", message)
    fmt.Printf("İmza (hex): %x\n", signature)
}
