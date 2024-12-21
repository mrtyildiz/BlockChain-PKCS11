package signature

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"

    pkcs11 "github.com/miekg/pkcs11"
)

func RSAVerftStr(slotID int, pin string, keyLabel string, Signauture string, signatureHex string) (string, error) {
    // PKCS#11 kütüphanesinin yolu (HSM ortamınıza göre ayarlayın)
    libPath := os.Getenv("PKCS11_LIB")
	message := []byte(Signauture)
    // İmza hex string'ini decode et
    signature, err := hex.DecodeString(signatureHex)

    if err != nil {
        fmt.Printf("İmza hex decode hatası: %v\n", err)
        os.Exit(1)
    }

    // PKCS#11 bağlamını oluştur
    p := pkcs11.New(libPath)
    if p == nil {
        fmt.Println("PKCS#11 kütüphanesi yüklenemedi.")
        os.Exit(1)
    }

    err = p.Initialize()
    if err != nil {
        fmt.Printf("Initialize hatası: %v\n", err)
        os.Exit(1)
    }
    defer p.Finalize()

    session, err := p.OpenSession(uint(slotID), pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
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
    // Public key objesini bul
    template := []*pkcs11.Attribute{
        pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
        pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
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
        fmt.Println("Belirtilen public key bulunamadı")
        os.Exit(1)
    }

    pubKeyHandle := objs[0]
    // Mesajı hash'le (SHA-256)
    hash := sha256.Sum256(message)

    // PKCS#1 v1.5 için SHA-256 DigestInfo (RFC 3447, Appendix B.1)
    digestInfoPrefix := []byte{
        0x30, 0x31, 0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86,
        0x48, 0x01, 0x65, 0x03,
        0x04, 0x02, 0x01, 0x05,
        0x00, 0x04, 0x20,
    }

    dataToVerify := append(digestInfoPrefix, hash[:]...)

    // VerifyInit başlat
    err = p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pubKeyHandle)
    if err != nil {
        fmt.Printf("VerifyInit hatası: %v\n", err)
        os.Exit(1)
    }

    // Verify çağrısı, imzayı doğrular
    err = p.Verify(session, dataToVerify, signature)
    if err != nil {
		fmt.Printf("İmza doğrulama hatası: %v\n", err)
		//return "", err // Hata durumunda fonksiyondan çıkılır ve hata döndürülür.
        return "Doğrulama başarısız", nil
    }
	return "Doğrulama başarılı", nil
}


// func main() {
//     sig, err := RSASignStr(0, "1111", "RSAKey3_pub", "Hello World", "1e1fbe1416a7bc91d0c69f97f328f45e371f33e728d3351246011412b80b6d7c796d8c1a024a54819318034042d4e39fd68bcb0acdb844b60bef9ecf59af3713c87b8a5c2d888c73856580742b2864f73fdb07a2f4ad336b9cd81bde3ac499ea24e69dfa8c736e34962c83dd943715327dbd26e539b100505cdc21fc61f51c75ed0345208f07ed42fd1511d52c66cdb1251242dd5d260bc0187be50a89eac24e22988e0feb5fe46c08093ad6fb360f126c0fc0184cea6c7ad3db9a87becadabe1706fe46b91cac3245a7f1a8a2a26b69f299c7d34d60fa10ae8a0297a7ec13577c5614fd0d26cf542980202f060d317beb3f24cbaca709314209c3245ebbe999")

//     if err != nil {
//         fmt.Printf("İmzalama hatası: %v\n", err)
//         os.Exit(1)
//     }

//     fmt.Printf("Oluşturulan İmza (hex): %s\n", sig)
// }
