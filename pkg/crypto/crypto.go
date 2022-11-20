/*
Copyright (c) 2022 - Present. Blend Labs, Inc. All rights reserved
Use of this source code is governed by a MIT license that can be found in the LICENSE file.
*/

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"

	cryptorand "crypto/rand"
	"github.com/blend/go-sdk/ex"
)

// Important constants.
const (
	// DefaultKeySize is the size of keys to generate for client use.
	DefaultKeySize = 32
	// KeyVersionSize is the size of the key version prefix.
	KeyVersionSize = (4 + 2 + 2 + 1) // YYYY + MM + DD + :
	// IVSize is the size of the IV prefix.
	IVSize = aes.BlockSize
	// HashSize is the size of the hash prefix.
	HashSize = 32 // reasons.
)

// NewStreamEncrypter creates a new stream encrypter
func NewStreamEncrypter(encKey, macKey []byte, plainText io.Reader) (*StreamEncrypter, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, ex.New(err)
	}
	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return nil, ex.New(err)
	}
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, macKey)
	return &StreamEncrypter{
		Source: plainText,
		Block:  block,
		Stream: stream,
		Mac:    mac,
		IV:     iv,
	}, nil
}

func NewStreamEncRestore(encKey, macKey []byte, meta StreamMeta, plainText io.Reader) (*StreamEncrypter, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, ex.New(err)
	}
	iv := make([]byte, block.BlockSize())
	copy(iv, meta.IV)
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, macKey)
	return &StreamEncrypter{
		Source: plainText,
		Block:  block,
		Stream: stream,
		Mac:    mac,
		IV:     iv,
	}, nil
}

// NewStreamDecrypter creates a new stream decrypter
func NewStreamDecrypter(encKey, macKey []byte, meta StreamMeta, cipherText io.Reader) (*StreamDecrypter, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, ex.New(err)
	}
	stream := cipher.NewCTR(block, meta.IV)
	mac := hmac.New(sha256.New, macKey)
	return &StreamDecrypter{
		Source: cipherText,
		Block:  block,
		Stream: stream,
		Mac:    mac,
		Meta:   meta,
	}, nil
}

// StreamEncrypter is an encrypter for a stream of data with authentication
type StreamEncrypter struct {
	Source io.Reader
	Block  cipher.Block
	Stream cipher.Stream
	Mac    hash.Hash
	IV     []byte
}

// StreamDecrypter is a decrypter for a stream of data with authentication
type StreamDecrypter struct {
	Source io.Reader
	Block  cipher.Block
	Stream cipher.Stream
	Mac    hash.Hash
	Meta   StreamMeta
}

// Read encrypts the bytes of the inner reader and places them into p
func (s *StreamEncrypter) Read(p []byte) (int, error) {
	n, readErr := s.Source.Read(p)
	if n > 0 {
		s.Stream.XORKeyStream(p[:n], p[:n])
		err := writeHash(s.Mac, p[:n])
		if err != nil {
			return n, ex.New(err)
		}
		return n, readErr
	}
	return 0, io.EOF
}

// Meta returns the encrypted stream metadata for use in decrypting. This should only be called after the stream is finished
func (s *StreamEncrypter) Meta() StreamMeta {
	return StreamMeta{IV: s.IV, Hash: s.Mac.Sum(nil)}
}

// Read reads bytes from the underlying reader and then decrypts them
func (s *StreamDecrypter) Read(p []byte) (int, error) {
	n, readErr := s.Source.Read(p)
	if n > 0 {
		err := writeHash(s.Mac, p[:n])
		if err != nil {
			return n, ex.New(err)
		}
		s.Stream.XORKeyStream(p[:n], p[:n])
		return n, readErr
	}
	return 0, io.EOF
}

// Authenticate verifys that the hash of the stream is correct. This should only be called after processing is finished
func (s *StreamDecrypter) Authenticate() error {
	if !hmac.Equal(s.Meta.Hash, s.Mac.Sum(nil)) {
		return ex.New("authentication failed")
	}
	return nil
}

func writeHash(mac hash.Hash, p []byte) error {
	m, err := mac.Write(p)
	if err != nil {
		return ex.New(err)
	}
	if m != len(p) {
		return ex.New("could not write all bytes to hmac")
	}
	return nil
}

func checkedWrite(dst io.Writer, p []byte) (int, error) {
	n, err := dst.Write(p)
	if err != nil {
		return n, ex.New(err)
	}
	if n != len(p) {
		return n, ex.New("unable to write all bytes")
	}
	return len(p), nil
}

// StreamMeta is metadata about an encrypted stream
type StreamMeta struct {
	// IV is the initial value for the crypto function
	IV []byte
	// Hash is the sha256 hmac of the stream
	Hash []byte
}

func StringToKey(input []byte) []byte {
	key := sha256.Sum256(input)
	return key[:]
}

// MustCreateKey creates a key, if an error is returned, it panics.
func MustCreateKey(keySize int) []byte {
	key, err := CreateKey(keySize)
	if err != nil {
		panic(err)
	}
	return key
}

// CreateKey creates a key of a given size by reading that much data off the crypto/rand reader.
func CreateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := cryptorand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// MustCreateKeyString generates a new key and returns it as a hex string.
func MustCreateKeyString(keySize int) string {
	return hex.EncodeToString(MustCreateKey(keySize))
}

// MustCreateKeyBase64String generates a new key and returns it as a base64 std encoding string.
func MustCreateKeyBase64String(keySize int) string {
	return base64.StdEncoding.EncodeToString(MustCreateKey(keySize))
}

// CreateKeyString generates a new key and returns it as a hex string.
func CreateKeyString(keySize int) (string, error) {
	key, err := CreateKey(keySize)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// CreateKeyBase64String generates a new key and returns it as a base64 std encoding string.
func CreateKeyBase64String(keySize int) (string, error) {
	key, err := CreateKey(keySize)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// ParseKey parses a key from a string.
func ParseKey(key string) ([]byte, error) {
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return nil, ex.New(err)
	}
	if len(decoded) != DefaultKeySize {
		return nil, ex.New("parse key; invalid key length")
	}
	return decoded, nil
}
