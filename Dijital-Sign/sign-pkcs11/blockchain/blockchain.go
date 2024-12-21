package blockchain

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/dgraph-io/badger/v3"
)

// Block yapısı
type Block struct {
	Index        int
	Timestamp    string
	Data         string
	Signature    string
	PreviousHash string
	Hash         string
}

// Blok hash hesaplama fonksiyonu
func (b *Block) calculateHash() string {
	record := string(b.Index) + b.Timestamp + b.Data + b.Signature + b.PreviousHash
	hash := sha256.Sum256([]byte(record))
	return fmt.Sprintf("%x", hash)
}

// Yeni blok oluşturma fonksiyonu
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

// Blockchain yapısı
type Blockchain struct {
	db     *badger.DB
	blocks []*Block
}

// Yeni blockchain oluşturma fonksiyonu
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

// Yeni blok ekleme fonksiyonu
func (bc *Blockchain) AddBlock(data, signature string) {
	previousBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(data, signature, previousBlock.Hash, len(bc.blocks))
	bc.saveBlock(newBlock)
	bc.blocks = append(bc.blocks, newBlock)
}

// Blokları kaydetme fonksiyonu
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

// Blokları yükleme fonksiyonu
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

// Blockchain'deki tüm blokları listeleme fonksiyonu
func (bc *Blockchain) ListData() []*Block {
	return bc.blocks
}

// Blockchain'i kapatma fonksiyonu
func (bc *Blockchain) Close() {
	bc.db.Close()
}
