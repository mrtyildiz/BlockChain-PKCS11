package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/dgraph-io/badger/v3"
)

type Block struct {
	Index        int
	Timestamp    string
	Data         string
	Signature    string
	PreviousHash string
	Hash         string
}

func (b *Block) calculateHash() string {
	record := string(b.Index) + b.Timestamp + b.Data + b.Signature + b.PreviousHash
	hash := sha256.Sum256([]byte(record))
	return fmt.Sprintf("%x", hash)
}

func NewBlock(data, signature, previousHash string, index int) *Block {
	block := &Block{
		Index:        index,
		Timestamp:    time.Now().String(),
		Data:         data,
		Signature:    signature,
		PreviousHash: previousHash,
	}
	block.Hash = block.calculateHash()
	return block
}

type Blockchain struct {
	db     *badger.DB
	blocks []*Block
}

func NewBlockchain() *Blockchain {
	opts := badger.DefaultOptions("./blockchaindb").WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatalf("BadgerDB başlatılamadı: %v", err)
	}

	blockchain := &Blockchain{db: db, blocks: []*Block{}}

	blockchain.loadBlocks()
	if len(blockchain.blocks) == 0 {
		genesisBlock := NewBlock("Genesis Block", "", "", 0)
		blockchain.saveBlock(genesisBlock)
		blockchain.blocks = append(blockchain.blocks, genesisBlock)
	}

	return blockchain
}

func (bc *Blockchain) AddBlock(data, signature string) {
	previousBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(data, signature, previousBlock.Hash, len(bc.blocks))
	bc.saveBlock(newBlock)
	bc.blocks = append(bc.blocks, newBlock)
}

func (bc *Blockchain) saveBlock(block *Block) {
	err := bc.db.Update(func(txn *badger.Txn) error {
		data, err := json.Marshal(block)
		if err != nil {
			return err
		}
		return txn.Set([]byte(fmt.Sprintf("block-%d", block.Index)), data)
	})
	if err != nil {
		log.Fatalf("Blok kaydedilemedi: %v", err)
	}
}

func (bc *Blockchain) loadBlocks() {
	err := bc.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := string(item.Key())

			if len(key) > 6 && key[:6] == "block-" {
				err := item.Value(func(val []byte) error {
					var block Block
					if err := json.Unmarshal(val, &block); err != nil {
						return err
					}
					bc.blocks = append(bc.blocks, &block)
					return nil
				})
				if err != nil {
					return err
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Bloklar yüklenemedi: %v", err)
	}
}

func (bc *Blockchain) Display() {
	for _, block := range bc.blocks {
		fmt.Printf("Index: %d\n", block.Index)
		fmt.Printf("Timestamp: %s\n", block.Timestamp)
		fmt.Printf("Data: %s\n", block.Data)
		fmt.Printf("Signature: %s\n", block.Signature)
		fmt.Printf("PreviousHash: %s\n", block.PreviousHash)
		fmt.Printf("Hash: %s\n", block.Hash)
		fmt.Println("---------------------------------")
	}
}

func (bc *Blockchain) ListData() {
	fmt.Println("Blockchain'deki Veriler:")
	for _, block := range bc.blocks {
		if block.Index == 0 {
			continue
		}
		fmt.Printf("Veri: %s, İmza: %s\n", block.Data, block.Signature)
	}
	fmt.Println("---------------------------------")
}

func main() {
	blockchain := NewBlockchain()
	defer blockchain.db.Close()

	blockchain.AddBlock("Bu bir string veridir.", "12345abcde")
	blockchain.AddBlock("İkinci string veri.", "54321edcba")
	blockchain.AddBlock("Üçüncü string veri.", "67890fghij")

	fmt.Println("Blockchain Yapısı:")
	blockchain.Display()

	blockchain.ListData()
}
