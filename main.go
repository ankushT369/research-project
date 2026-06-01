package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image/color"
	"image/png"
	"io"
	"log"
	// "math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/disintegration/imaging"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/chacha20poly1305"
)

// ==================== Crypto Interfaces ====================

type Cipher interface {
	Name() string
	Encrypt(plaintext []byte) (key []byte, ciphertext []byte, err error)
	Decrypt(key []byte, ciphertext []byte) ([]byte, error)
}

type ChaCha20Cipher struct {
	keySize   int
	nonceSize int
}

func NewChaCha20Cipher() *ChaCha20Cipher {
	return &ChaCha20Cipher{
		keySize:   chacha20poly1305.KeySize,
		nonceSize: chacha20poly1305.NonceSize,
	}
}

func (c *ChaCha20Cipher) Name() string { return "CHACHA20" }

func (c *ChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	key := make([]byte, c.keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, c.nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return key, append(nonce, ciphertext...), nil
}

func (c *ChaCha20Cipher) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < c.nonceSize {
		return nil, fmt.Errorf("invalid ciphertext")
	}
	nonce := ciphertext[:c.nonceSize]
	encrypted := ciphertext[c.nonceSize:]
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, encrypted, nil)
}

// ==================== Crypto Layer ====================

type CryptoLayer struct {
	cipher Cipher
}

func NewCryptoLayer(cipher Cipher) *CryptoLayer {
	return &CryptoLayer{cipher: cipher}
}

func (cl *CryptoLayer) BuildSecretForSharing(message string) (string, error) {
	msgBytes := []byte(message)
	hash := sha256.Sum256(msgBytes)
	plaintext := append(hash[:], msgBytes...)

	key, ciphertext, err := cl.cipher.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	keyB64 := base64.StdEncoding.EncodeToString(key)
	cipherB64 := base64.StdEncoding.EncodeToString(ciphertext)
	lengthTag := len(keyB64 + cipherB64)

	return fmt.Sprintf("%s:%d:%s:%s", cl.cipher.Name(), lengthTag, keyB64, cipherB64), nil
}

func (cl *CryptoLayer) RecoverMessageFromSecret(secretStr string) (string, error) {
	parts := strings.SplitN(secretStr, ":", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("invalid secret format")
	}

	if parts[0] != cl.cipher.Name() {
		return "", fmt.Errorf("expected %s, got %s", cl.cipher.Name(), parts[0])
	}

	var length int
	fmt.Sscanf(parts[1], "%d", &length)

	keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", err
	}

	plaintext, err := cl.cipher.Decrypt(keyBytes, cipherBytes)
	if err != nil {
		return "", err
	}

	if len(plaintext) < 32 {
		return "", fmt.Errorf("plaintext too short")
	}

	storedHash := plaintext[:32]
	messageBytes := plaintext[32:]
	calculatedHash := sha256.Sum256(messageBytes)

	for i := 0; i < 32; i++ {
		if storedHash[i] != calculatedHash[i] {
			return "", fmt.Errorf("hash verification failed")
		}
	}

	return string(messageBytes), nil
}

// ==================== BNB Secret Sharing Scheme ====================

// Combination generator - generates all combinations of n bits with exactly k zeros
func generateCombinations(n, k int) [][]int {
	if k < 0 || k > n {
		return nil
	}

	result := make([][]int, 0)
	bits := make([]int, n)

	// Initialize: first k zeros, then n-k ones
	for i := 0; i < k; i++ {
		bits[i] = 0
	}
	for i := k; i < n; i++ {
		bits[i] = 1
	}

	// Add first combination
	temp := make([]int, n)
	copy(temp, bits)
	result = append(result, temp)

	// Generate all combinations using next_combination algorithm
	for {
		// Find the rightmost 01 pattern
		i := n - 2
		for i >= 0 && !(bits[i] == 0 && bits[i+1] == 1) {
			i--
		}
		if i < 0 {
			break
		}

		// Swap
		bits[i], bits[i+1] = bits[i+1], bits[i]

		// Reverse the suffix after i+1
		left, right := i+2, n-1
		for left < right {
			bits[left], bits[right] = bits[right], bits[left]
			left++
			right--
		}

		temp := make([]int, n)
		copy(temp, bits)
		result = append(result, temp)
	}

	return result
}

// Factorial
func factorial(n int) int {
	if n <= 1 {
		return 1
	}
	result := 1
	for i := 2; i <= n; i++ {
		result *= i
	}
	return result
}

// Combination C(n, r)
func comb(n, r int) int {
	if r < 0 || r > n {
		return 0
	}
	return factorial(n) / (factorial(r) * factorial(n-r))
}

type BNBSecretSharing struct {
	k int // minimum shares needed
	n int // total shares
	m int // mandatory shares count
}

func NewBNBSecretSharing(k, n, m int) *BNBSecretSharing {
	return &BNBSecretSharing{
		k: k,
		n: n,
		m: m,
	}
}

// Generate shares using the BNB algorithm from the paper
func (bnb *BNBSecretSharing) GenerateShares(secretBits []int) ([][]int, error) {
	secretLen := len(secretBits)
	comboSize := comb(bnb.n, bnb.k-1)
	maskWidth := comboSize + bnb.m

	// Step 1: Generate all combinations of n bits with exactly k-1 zeros
	combinations := generateCombinations(bnb.n, bnb.k-1)

	// Step 2: Build mask matrix
	// Transpose: each share gets a mask row
	masks := make([][]int, bnb.n)
	for i := 0; i < bnb.n; i++ {
		masks[i] = make([]int, maskWidth)
	}

	// Fill first comboSize columns with combinations
	for col := 0; col < comboSize && col < len(combinations); col++ {
		combo := combinations[col]
		for row := 0; row < bnb.n && row < len(combo); row++ {
			masks[row][col] = combo[row]
		}
	}

	// Fill mandatory mask columns (last m columns)
	for i := 0; i < bnb.m; i++ {
		for j := 0; j < bnb.n; j++ {
			if j == i {
				masks[j][comboSize+i] = 1
			} else {
				masks[j][comboSize+i] = 0
			}
		}
	}

	// Step 3: Repeat masks to match secret length
	repeatedMasks := make([][]int, bnb.n)
	for i := 0; i < bnb.n; i++ {
		repeats := secretLen / maskWidth
		remainder := secretLen % maskWidth

		repeatedMasks[i] = make([]int, secretLen)
		for r := 0; r < repeats; r++ {
			for j := 0; j < maskWidth; j++ {
				repeatedMasks[i][r*maskWidth+j] = masks[i][j]
			}
		}
		for j := 0; j < remainder; j++ {
			repeatedMasks[i][repeats*maskWidth+j] = masks[i][j]
		}
	}

	// Step 4: Generate shares by ANDing masks with secret
	shares := make([][]int, bnb.n)
	for i := 0; i < bnb.n; i++ {
		shares[i] = make([]int, secretLen)
		for j := 0; j < secretLen; j++ {
			shares[i][j] = repeatedMasks[i][j] & secretBits[j]
		}
	}

	return shares, nil
}

// Reconstruct secret using OR of any K shares that include all mandatory shares
func (bnb *BNBSecretSharing) ReconstructSecret(shares [][]int) ([]int, error) {
	if len(shares) < bnb.k {
		return nil, fmt.Errorf("need at least %d shares, got %d", bnb.k, len(shares))
	}

	// Find minimum length among shares
	minLen := len(shares[0])
	for _, s := range shares {
		if len(s) < minLen {
			minLen = len(s)
		}
	}

	// OR all shares
	result := make([]int, minLen)
	for i := 0; i < minLen; i++ {
		for _, s := range shares {
			if s[i] == 1 {
				result[i] = 1
				break
			}
		}
	}

	return result, nil
}

// Helper: Convert string to bits
func stringToBits(s string) []int {
	byteData := []byte(s)
	bits := make([]int, 0)
	for _, b := range byteData {
		for i := 7; i >= 0; i-- {
			bits = append(bits, int((b>>uint(i))&1))
		}
	}
	return bits
}

// Helper: Convert bits to string
func bitsToString(bits []int) string {
	if len(bits)%8 != 0 {
		bits = bits[:len(bits)-(len(bits)%8)]
	}
	byteData := make([]byte, 0)
	for i := 0; i < len(bits); i += 8 {
		var val byte
		for j := 0; j < 8; j++ {
			val = (val << 1) | byte(bits[i+j])
		}
		byteData = append(byteData, val)
	}
	return string(byteData)
}

// ==================== Steganography ====================

func EmbedShareInImage(shareBits []int, inputPath, outputPath string, isMandatory bool) error {
	img, err := imaging.Open(inputPath)
	if err != nil {
		return err
	}

	bounds := img.Bounds()
	flat := make([]uint8, 0)
	for y := 0; y < bounds.Max.Y; y++ {
		for x := 0; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			flat = append(flat, uint8(r>>8), uint8(g>>8), uint8(b>>8))
		}
	}

	// Header: mandatory flag (1) + length (32 bits)
	header := make([]int, 0)
	if isMandatory {
		header = append(header, 1)
	} else {
		header = append(header, 0)
	}

	shareLen := len(shareBits)
	for i := 31; i >= 0; i-- {
		header = append(header, (shareLen>>uint(i))&1)
	}

	data := append(header, shareBits...)

	if len(data) > len(flat) {
		return fmt.Errorf("share too large for image")
	}

	for i, bit := range data {
		if bit == 1 {
			flat[i] = flat[i] | 1
		} else {
			flat[i] = flat[i] & 0xFE
		}
	}

	newImg := imaging.New(bounds.Max.X, bounds.Max.Y, color.NRGBA{})
	idx := 0
	for y := 0; y < bounds.Max.Y; y++ {
		for x := 0; x < bounds.Max.X; x++ {
			newImg.SetNRGBA(x, y, color.NRGBA{R: flat[idx], G: flat[idx+1], B: flat[idx+2], A: 255})
			idx += 3
		}
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	return png.Encode(out, newImg)
}

func ExtractShareFromImage(imagePath string) (bool, []int, error) {
	img, err := imaging.Open(imagePath)
	if err != nil {
		return false, nil, err
	}

	bounds := img.Bounds()
	flat := make([]uint8, 0)
	for y := 0; y < bounds.Max.Y; y++ {
		for x := 0; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			flat = append(flat, uint8(r>>8), uint8(g>>8), uint8(b>>8))
		}
	}

	if len(flat) < 33 {
		return false, nil, fmt.Errorf("image too small")
	}

	flag := (flat[0] & 1) == 1

	lengthBits := 0
	for i := 1; i < 33; i++ {
		lengthBits = (lengthBits << 1) | int(flat[i]&1)
	}
	shareLength := lengthBits

	if shareLength > len(flat)-33 {
		shareLength = len(flat) - 33
	}

	shareBits := make([]int, shareLength)
	for i := 0; i < shareLength; i++ {
		shareBits[i] = int(flat[33+i] & 1)
	}

	return flag, shareBits, nil
}

// ==================== Server ====================

type Server struct {
	router  *gin.Engine
	uploads string
	shares  string
}

func NewServer() *Server {
	s := &Server{
		router:  gin.Default(),
		uploads: "uploads",
		shares:  "shares",
	}
	os.MkdirAll(s.uploads, 0755)
	os.MkdirAll(s.shares, 0755)
	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	s.router.Static("/static", "./static")
	s.router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
	s.router.POST("/api/generate", s.handleGenerate)
	s.router.POST("/api/reconstruct", s.handleReconstruct)
	s.router.GET("/api/download/:filename", s.handleDownload)
}

func (s *Server) handleGenerate(c *gin.Context) {
	kStr := c.PostForm("k")
	nStr := c.PostForm("n")
	mStr := c.PostForm("m")
	secret := c.PostForm("secret")

	k, _ := strconv.Atoi(kStr)
	n, _ := strconv.Atoi(nStr)
	m, _ := strconv.Atoi(mStr)

	log.Printf("Generating: k=%d, n=%d, m=%d", k, n, m)

	// Encrypt secret
	cipher := NewChaCha20Cipher()
	cryptoLayer := NewCryptoLayer(cipher)
	encryptedSecret, err := cryptoLayer.BuildSecretForSharing(secret)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Convert to bits
	secretBits := stringToBits(encryptedSecret)

	// Generate shares using BNB scheme
	bnb := NewBNBSecretSharing(k, n, m)
	shares, err := bnb.GenerateShares(secretBits)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Handle carrier image - user uploaded or default
	var carrierImg string
	file, header, err := c.Request.FormFile("carrier")
	if err == nil {
		// User uploaded a carrier image
		defer file.Close()

		// Validate file type
		ext := strings.ToLower(filepath.Ext(header.Filename))
		if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
			c.JSON(400, gin.H{"error": "Carrier image must be PNG or JPEG"})
			return
		}

		// Save uploaded carrier temporarily
		carrierImg = filepath.Join(s.uploads, "carrier_"+header.Filename)
		out, err := os.Create(carrierImg)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to save carrier image"})
			return
		}
		defer out.Close()
		io.Copy(out, file)
		log.Printf("Using uploaded carrier image: %s", header.Filename)
	} else {
		// Use default carrier image
		carrierImg = "./static/input.png"
		if _, err := os.Stat(carrierImg); os.IsNotExist(err) {
			s.createDefaultImage(carrierImg)
		}
		log.Println("Using default carrier image")
	}

	// Clear previous shares
	os.RemoveAll(s.shares)
	os.MkdirAll(s.shares, 0755)

	response := struct {
		Shares []struct {
			ID        int    `json:"id"`
			Mandatory bool   `json:"mandatory"`
			URL       string `json:"url"`
		} `json:"shares"`
	}{}

	for i, share := range shares {
		isMandatory := i < m
		filename := fmt.Sprintf("share_%d.png", i)
		filepath := filepath.Join(s.shares, filename)

		if err := EmbedShareInImage(share, carrierImg, filepath, isMandatory); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		response.Shares = append(response.Shares, struct {
			ID        int    `json:"id"`
			Mandatory bool   `json:"mandatory"`
			URL       string `json:"url"`
		}{ID: i, Mandatory: isMandatory, URL: "/api/download/" + filename})
	}

	log.Printf("Generated %d shares successfully", len(shares))
	c.JSON(200, response)
}

// func (s *Server) handleGenerate(c *gin.Context) {
//     kStr := c.PostForm("k")
//     nStr := c.PostForm("n")
//     mStr := c.PostForm("m")
//     secret := c.PostForm("secret")
//
//     k, _ := strconv.Atoi(kStr)
//     n, _ := strconv.Atoi(nStr)
//     m, _ := strconv.Atoi(mStr)
//
//     log.Printf("Generating: k=%d, n=%d, m=%d", k, n, m)
//
//     // Encrypt secret
//     cipher := NewChaCha20Cipher()
//     cryptoLayer := NewCryptoLayer(cipher)
//     encryptedSecret, err := cryptoLayer.BuildSecretForSharing(secret)
//     if err != nil {
//         c.JSON(500, gin.H{"error": err.Error()})
//         return
//     }
//
//     // Convert to bits
//     secretBits := stringToBits(encryptedSecret)
//
//     // Generate shares using BNB scheme
//     bnb := NewBNBSecretSharing(k, n, m)
//     shares, err := bnb.GenerateShares(secretBits)
//     if err != nil {
//         c.JSON(500, gin.H{"error": err.Error()})
//         return
//     }
//
//     // Default carrier image
//     carrierImg := "./static/input.png"
//     if _, err := os.Stat(carrierImg); os.IsNotExist(err) {
//         s.createDefaultImage(carrierImg)
//     }
//
//     // Clear previous shares
//     os.RemoveAll(s.shares)
//     os.MkdirAll(s.shares, 0755)
//
//     response := struct {
//         Shares []struct {
//             ID        int    `json:"id"`
//             Mandatory bool   `json:"mandatory"`
//             URL       string `json:"url"`
//         } `json:"shares"`
//     }{}
//
//     for i, share := range shares {
//         isMandatory := i < m
//         filename := fmt.Sprintf("share_%d.png", i)
//         filepath := filepath.Join(s.shares, filename)
//
//         if err := EmbedShareInImage(share, carrierImg, filepath, isMandatory); err != nil {
//             c.JSON(500, gin.H{"error": err.Error()})
//             return
//         }
//
//         response.Shares = append(response.Shares, struct {
//             ID        int    `json:"id"`
//             Mandatory bool   `json:"mandatory"`
//             URL       string `json:"url"`
//         }{ID: i, Mandatory: isMandatory, URL: "/api/download/" + filename})
//     }
//
//     log.Printf("Generated %d shares successfully", len(shares))
//     c.JSON(200, response)
// }

func (s *Server) handleReconstruct(c *gin.Context) {
	kStr := c.PostForm("k")
	mStr := c.PostForm("m")

	k, _ := strconv.Atoi(kStr)
	m, _ := strconv.Atoi(mStr)

	log.Printf("Reconstructing: k=%d, m=%d", k, m)

	// Get uploaded files
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	files := form.File["shares"]
	if len(files) < k {
		c.JSON(400, gin.H{"error": fmt.Sprintf("Need at least %d shares, got %d", k, len(files))})
		return
	}

	// Extract shares from images
	var extractedShares [][]int
	var mandatoryCount int

	for idx, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		tmpPath := filepath.Join(s.uploads, fmt.Sprintf("temp_%d_%s", idx, fileHeader.Filename))
		tmpFile, err := os.Create(tmpPath)
		if err != nil {
			file.Close()
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		io.Copy(tmpFile, file)
		tmpFile.Close()
		file.Close()
		defer os.Remove(tmpPath)

		isMandatory, bits, err := ExtractShareFromImage(tmpPath)
		if err != nil {
			c.JSON(500, gin.H{"error": fmt.Sprintf("Failed to extract from %s: %v", fileHeader.Filename, err)})
			return
		}

		if isMandatory {
			mandatoryCount++
		}
		extractedShares = append(extractedShares, bits)
		log.Printf("File %s: mandatory=%v, bits=%d", fileHeader.Filename, isMandatory, len(bits))
	}

	if mandatoryCount < m {
		c.JSON(400, gin.H{"error": fmt.Sprintf("Need %d mandatory shares, got %d", m, mandatoryCount)})
		return
	}

	// Use first k shares (or you can use any k shares)
	sharesToReconstruct := extractedShares[:k]

	// Reconstruct using BNB scheme
	bnb := NewBNBSecretSharing(k, 0, m)
	reconstructedBits, err := bnb.ReconstructSecret(sharesToReconstruct)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Convert bits to string
	reconstructedSecret := bitsToString(reconstructedBits)

	// Clean and decrypt
	cleaned := reconstructedSecret
	cipher := NewChaCha20Cipher()
	cryptoLayer := NewCryptoLayer(cipher)
	message, err := cryptoLayer.RecoverMessageFromSecret(cleaned)
	if err != nil {
		log.Printf("Decryption error: %v", err)
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"secret": message})
}

func (s *Server) handleDownload(c *gin.Context) {
	filename := c.Param("filename")
	filepath := filepath.Join(s.shares, filename)

	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		c.JSON(404, gin.H{"error": "File not found"})
		return
	}

	c.File(filepath)
}

func (s *Server) createDefaultImage(path string) {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)
	img := imaging.New(800, 600, color.NRGBA{R: 128, G: 128, B: 128, A: 255})
	imaging.Save(img, path)
}

func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

func main() {
	srv := NewServer()
	log.Println("Server running on http://localhost:8080")
	log.Println("Secret Sharing Scheme - ANY k shares including mandatory can reconstruct")
	log.Fatal(srv.Run(":8080"))
}
