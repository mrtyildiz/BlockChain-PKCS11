// /go-pkcs11/main.go
package main

import (
	"fmt"
	"sign-pkcs11/create"
	"sign-pkcs11/signature"
	"sign-pkcs11/blockchain"
	"net/http"
	"github.com/gin-gonic/gin"
)


type KeyRSARequest struct {
	SlotID   int   `json:"SlotId"`
	UserPin  string `json:"UserPin" binding:"required"`
	KeySize  int    `json:"KeySize" binding:"required"`
	KeyLabel string `json:"KeyLabel" binding:"required"`
}

type RSATextSign struct	{
	SlotID   int   `json:"SlotId"`
	UserPin  string `json:"UserPin" binding:"required"`
	KeyLabel string `json:"KeyLabel" binding:"required"`
	Signauture string `json:"Signauture" binding:"required"`
}

type RSATextVerifty struct	{
	SlotID   int   `json:"SlotId"`
	UserPin  string `json:"UserPin" binding:"required"`
	KeyLabel string `json:"KeyLabel" binding:"required"`
	Signauture string `json:"Signauture" binding:"required"`
	SignautureHex string `json:"SignautureHex" binding:"required"`

}

type BlockChainObje struct	{
	Data      string `json:"Data" binding:"required"`
	Signature string `json:"Signature" binding:"required"`
}

func main() {
    router := gin.Default()


	// Blockchain'i başlat
	bc := blockchain.NewBlockchain()
	defer bc.Close()

	// Yeni blok ekleme endpoint'i
	router.POST("/BlockChain/Add", func(c *gin.Context) {
		var request BlockChainObje

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		bc.AddBlock(request.Data, request.Signature)
		c.JSON(http.StatusOK, gin.H{"message": "Yeni blok eklendi."})
	})
	router.GET("/BlockChain/List", func(c *gin.Context) {
		blocks := bc.ListData()
		c.JSON(http.StatusOK, blocks)
	})

	router.POST("/RSA/Text/Verifty", func(c *gin.Context) {
		var req RSATextVerifty
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		result, err := signature.RSAVerftStr(req.SlotID, req.UserPin, req.KeyLabel, req.Signauture, req.SignautureHex)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": result})
	})
	



	router.POST("/RSA/Text/Signature", func(c *gin.Context) {
		var req RSATextSign
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		fmt.Println(req.SlotID)
		result, err := signature.RSASignStr(req.SlotID, req.UserPin, req.KeyLabel, req.Signauture)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": result})
	})
	    	// POST endpoint for key generation
	router.POST("/create/rsaCreate", func(c *gin.Context) {
		var req KeyRSARequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// RSA anahtar oluşturma
		fmt.Println(req.SlotID)
		result, err := create.GenerateRSAKey(req.SlotID, req.UserPin, req.KeySize, req.KeyLabel)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": result})
	})
	



    router.Run(":8080")
}
// EC import işlemi için Start
