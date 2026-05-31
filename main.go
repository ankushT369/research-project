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
    "math/big"
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

// ==================== Secret Sharing ====================

type BitCombinations struct {
    k               int
    n               int
    m               int
    secretBits      []int
    secretLen       int
    CombinedANDMask [][]int
}

func NewBitCombinations(k, n, m int, secretText string) (*BitCombinations, error) {
    if !(m <= k && k <= n) {
        return nil, fmt.Errorf("must satisfy m <= k <= n")
    }
    bc := &BitCombinations{k: k, n: n, m: m}
    
    // Only convert to bits if we have a secret (for generation)
    if secretText != "" {
        if err := bc.stringToBits(secretText); err != nil {
            return nil, err
        }
    }
    
    return bc, nil
}

func (bc *BitCombinations) stringToBits(secret string) error {
    byteData := []byte(secret)
    bc.secretBits = make([]int, 0)
    for _, b := range byteData {
        for i := 7; i >= 0; i-- {
            bc.secretBits = append(bc.secretBits, int((b>>uint(i))&1))
        }
    }
    bc.secretLen = len(bc.secretBits)
    return nil
}

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

func (bc *BitCombinations) ShareGeneration() error {
    // Generate random bits for first (k-1) shares
    randomShares := make([][]int, bc.k-1)
    for i := 0; i < bc.k-1; i++ {
        randomShares[i] = make([]int, bc.secretLen)
        for j := 0; j < bc.secretLen; j++ {
            bit, _ := rand.Int(rand.Reader, big.NewInt(2))
            randomShares[i][j] = int(bit.Int64())
        }
    }

    // Last share = secret XOR (XOR of all random shares)
    lastShare := make([]int, bc.secretLen)
    copy(lastShare, bc.secretBits)
    for _, rs := range randomShares {
        for j := 0; j < bc.secretLen; j++ {
            lastShare[j] ^= rs[j]
        }
    }

    reconstructionShares := append(randomShares, lastShare)

    // Create n shares
    allShares := make([][]int, 0)
    for i := 0; i < bc.m && i < len(reconstructionShares); i++ {
        share := make([]int, bc.secretLen)
        copy(share, reconstructionShares[i])
        allShares = append(allShares, share)
    }
    for i := bc.m; i < len(reconstructionShares); i++ {
        if len(allShares) < bc.n {
            share := make([]int, bc.secretLen)
            copy(share, reconstructionShares[i])
            allShares = append(allShares, share)
        }
    }
    for len(allShares) < bc.n {
        dummy := make([]int, bc.secretLen)
        for j := 0; j < bc.secretLen; j++ {
            bit, _ := rand.Int(rand.Reader, big.NewInt(2))
            dummy[j] = int(bit.Int64())
        }
        allShares = append(allShares, dummy)
    }

    bc.CombinedANDMask = allShares
    return nil
}

func (bc *BitCombinations) ReconstructSecret(selectedShares [][]int) (string, error) {
    if bc.k == 0 {
        return "", fmt.Errorf("k value not set for reconstruction")
    }
    
    if len(selectedShares) < bc.k {
        return "", fmt.Errorf("need at least %d shares, got %d", bc.k, len(selectedShares))
    }

    minLen := len(selectedShares[0])
    for _, s := range selectedShares {
        if len(s) < minLen {
            minLen = len(s)
        }
    }

    result := make([]int, minLen)
    copy(result, selectedShares[0][:minLen])
    for i := 1; i < len(selectedShares); i++ {
        for j := 0; j < minLen; j++ {
            result[j] ^= selectedShares[i][j]
        }
    }

    return bitsToString(result), nil
}

func (bc *BitCombinations) GetShares() [][]int {
    return bc.CombinedANDMask
}

func CleanSecret(secret string) string {
    parts := strings.SplitN(secret, ":", 4)
    if len(parts) < 4 {
        return secret
    }

    var length int
    fmt.Sscanf(parts[1], "%d", &length)

    totalLen := len(parts[2] + parts[3])
    if totalLen > length {
        excess := totalLen - length
        if excess <= len(parts[3]) {
            parts[3] = parts[3][:len(parts[3])-excess]
        }
    }

    return fmt.Sprintf("%s:%s:%s:%s", parts[0], parts[1], parts[2], parts[3])
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

type GenerateRequest struct {
    K       int    `json:"k"`
    N       int    `json:"n"`
    M       int    `json:"m"`
    Secret  string `json:"secret"`
    Cipher  string `json:"cipher"`
    UseFile bool   `json:"useFile"`
}

type GenerateResponse struct {
    Shares []struct {
        ID        int    `json:"id"`
        Mandatory bool   `json:"mandatory"`
        URL       string `json:"url"`
    } `json:"shares"`
}

func (s *Server) handleGenerate(c *gin.Context) {
    var req GenerateRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    secret := req.Secret

    // Choose cipher
    cipher := NewChaCha20Cipher()

    // Build secret
    cryptoLayer := NewCryptoLayer(cipher)
    encryptedSecret, err := cryptoLayer.BuildSecretForSharing(secret)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    // Generate shares
    bc, err := NewBitCombinations(req.K, req.N, req.M, encryptedSecret)
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    if err := bc.ShareGeneration(); err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    shares := bc.GetShares()

    // Default carrier image
    carrierImg := "./static/input.png"
    if _, err := os.Stat(carrierImg); os.IsNotExist(err) {
        s.createDefaultImage(carrierImg)
    }

    // Clear previous shares
    os.RemoveAll(s.shares)
    os.MkdirAll(s.shares, 0755)

    response := GenerateResponse{}
    for i, share := range shares {
        isMandatory := i < req.M
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

    c.JSON(200, response)
}

func (s *Server) handleReconstruct(c *gin.Context) {
    // Get form values
    kStr := c.PostForm("k")
    mStr := c.PostForm("m")

    k, err := strconv.Atoi(kStr)
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid k value"})
        return
    }
    
    m, err := strconv.Atoi(mStr)
    if err != nil {
        c.JSON(400, gin.H{"error": "Invalid m value"})
        return
    }

    log.Printf("Reconstructing with k=%d, m=%d", k, m)

    // Get uploaded files
    form, err := c.MultipartForm()
    if err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }

    files := form.File["shares"]
    if len(files) == 0 {
        c.JSON(400, gin.H{"error": "No shares uploaded"})
        return
    }

    log.Printf("Received %d files for reconstruction", len(files))

    // Extract shares from images
    var mandatoryShares [][]int
    var normalShares [][]int

    for idx, fileHeader := range files {
        // Open the file
        file, err := fileHeader.Open()
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }

        // Save temporarily
        tmpPath := filepath.Join(s.uploads, fmt.Sprintf("share_%d_%s", idx, fileHeader.Filename))
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

        // Extract share
        isMandatory, bits, err := ExtractShareFromImage(tmpPath)
        if err != nil {
            c.JSON(500, gin.H{"error": fmt.Sprintf("Failed to extract from %s: %v", fileHeader.Filename, err)})
            return
        }

        log.Printf("File %s: mandatory=%v, bits=%d", fileHeader.Filename, isMandatory, len(bits))

        if isMandatory {
            mandatoryShares = append(mandatoryShares, bits)
        } else {
            normalShares = append(normalShares, bits)
        }
    }

    log.Printf("Mandatory shares: %d, Normal shares: %d", len(mandatoryShares), len(normalShares))

    // Check mandatory count
    if len(mandatoryShares) < m {
        c.JSON(400, gin.H{"error": fmt.Sprintf("Need %d mandatory shares, got %d", m, len(mandatoryShares))})
        return
    }

    // Select shares for reconstruction
    selected := make([][]int, 0)
    selected = append(selected, mandatoryShares[:m]...)
    
    remainingNeeded := k - m
    if len(normalShares) < remainingNeeded {
        c.JSON(400, gin.H{"error": fmt.Sprintf("Need %d more normal shares, got %d", remainingNeeded, len(normalShares))})
        return
    }
    selected = append(selected, normalShares[:remainingNeeded]...)

    log.Printf("Selected %d shares for reconstruction", len(selected))

    // Reconstruct - create bc with proper k value
    bc := &BitCombinations{k: k, n: 0, m: m}
    secret, err := bc.ReconstructSecret(selected)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    log.Printf("Reconstructed secret length: %d", len(secret))

    // Clean and decrypt
    cleaned := CleanSecret(secret)
    cipher := NewChaCha20Cipher()
    cryptoLayer := NewCryptoLayer(cipher)
    message, err := cryptoLayer.RecoverMessageFromSecret(cleaned)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }

    c.JSON(200, gin.H{"secret": message})
}

func (s *Server) handleDownload(c *gin.Context) {
    filename := c.Param("filename")
    filepath := filepath.Join(s.shares, filename)
    
    // Check if file exists
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
    err := imaging.Save(img, path)
    if err != nil {
        log.Printf("Failed to create default image: %v", err)
    }
}

func (s *Server) Run(addr string) error {
    return s.router.Run(addr)
}

func main() {
    srv := NewServer()
    log.Println("🚀 Server running on http://localhost:8080")
    log.Println("📤 Generate shares with k,n,m parameters")
    log.Println("🔓 Reconstruct with uploaded share images")
    log.Fatal(srv.Run(":8080"))
}

// package main
//
// import (
//     "crypto/rand"
//     "crypto/sha256"
//     "encoding/base64"
//     "fmt"
//     "image/color"
//     "image/png"
//     "io"
//     "log"
//     "math/big"
//     "os"
//     "path/filepath"
//     "strconv"
//     "strings"
//
//     "github.com/disintegration/imaging"
//     "github.com/gin-gonic/gin"
//     "golang.org/x/crypto/chacha20poly1305"
// )
//
// // ==================== Crypto Interfaces ====================
//
// type Cipher interface {
//     Name() string
//     Encrypt(plaintext []byte) (key []byte, ciphertext []byte, err error)
//     Decrypt(key []byte, ciphertext []byte) ([]byte, error)
// }
//
// type ChaCha20Cipher struct {
//     keySize   int
//     nonceSize int
// }
//
// func NewChaCha20Cipher() *ChaCha20Cipher {
//     return &ChaCha20Cipher{
//         keySize:   chacha20poly1305.KeySize,
//         nonceSize: chacha20poly1305.NonceSize,
//     }
// }
//
// func (c *ChaCha20Cipher) Name() string { return "CHACHA20" }
//
// func (c *ChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
//     key := make([]byte, c.keySize)
//     if _, err := io.ReadFull(rand.Reader, key); err != nil {
//         return nil, nil, err
//     }
//     nonce := make([]byte, c.nonceSize)
//     if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
//         return nil, nil, err
//     }
//     aead, err := chacha20poly1305.New(key)
//     if err != nil {
//         return nil, nil, err
//     }
//     ciphertext := aead.Seal(nil, nonce, plaintext, nil)
//     return key, append(nonce, ciphertext...), nil
// }
//
// func (c *ChaCha20Cipher) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
//     if len(ciphertext) < c.nonceSize {
//         return nil, fmt.Errorf("invalid ciphertext")
//     }
//     nonce := ciphertext[:c.nonceSize]
//     encrypted := ciphertext[c.nonceSize:]
//     aead, err := chacha20poly1305.New(key)
//     if err != nil {
//         return nil, err
//     }
//     return aead.Open(nil, nonce, encrypted, nil)
// }
//
// // ==================== Crypto Layer ====================
//
// type CryptoLayer struct {
//     cipher Cipher
// }
//
// func NewCryptoLayer(cipher Cipher) *CryptoLayer {
//     return &CryptoLayer{cipher: cipher}
// }
//
// func (cl *CryptoLayer) BuildSecretForSharing(message string) (string, error) {
//     msgBytes := []byte(message)
//     hash := sha256.Sum256(msgBytes)
//     plaintext := append(hash[:], msgBytes...)
//
//     key, ciphertext, err := cl.cipher.Encrypt(plaintext)
//     if err != nil {
//         return "", err
//     }
//
//     keyB64 := base64.StdEncoding.EncodeToString(key)
//     cipherB64 := base64.StdEncoding.EncodeToString(ciphertext)
//     lengthTag := len(keyB64 + cipherB64)
//
//     return fmt.Sprintf("%s:%d:%s:%s", cl.cipher.Name(), lengthTag, keyB64, cipherB64), nil
// }
//
// func (cl *CryptoLayer) RecoverMessageFromSecret(secretStr string) (string, error) {
//     parts := strings.SplitN(secretStr, ":", 4)
//     if len(parts) != 4 {
//         return "", fmt.Errorf("invalid secret format")
//     }
//
//     if parts[0] != cl.cipher.Name() {
//         return "", fmt.Errorf("expected %s, got %s", cl.cipher.Name(), parts[0])
//     }
//
//     var length int
//     fmt.Sscanf(parts[1], "%d", &length)
//
//     keyBytes, err := base64.StdEncoding.DecodeString(parts[2])
//     if err != nil {
//         return "", err
//     }
//     cipherBytes, err := base64.StdEncoding.DecodeString(parts[3])
//     if err != nil {
//         return "", err
//     }
//
//     plaintext, err := cl.cipher.Decrypt(keyBytes, cipherBytes)
//     if err != nil {
//         return "", err
//     }
//
//     if len(plaintext) < 32 {
//         return "", fmt.Errorf("plaintext too short")
//     }
//
//     storedHash := plaintext[:32]
//     messageBytes := plaintext[32:]
//     calculatedHash := sha256.Sum256(messageBytes)
//
//     for i := 0; i < 32; i++ {
//         if storedHash[i] != calculatedHash[i] {
//             return "", fmt.Errorf("hash verification failed")
//         }
//     }
//
//     return string(messageBytes), nil
// }
//
// // ==================== Secret Sharing ====================
//
// type BitCombinations struct {
//     k               int
//     n               int
//     m               int
//     secretBits      []int
//     secretLen       int
//     CombinedANDMask [][]int
// }
//
// func NewBitCombinations(k, n, m int, secretText string) (*BitCombinations, error) {
//     if !(m <= k && k <= n) {
//         return nil, fmt.Errorf("must satisfy m <= k <= n")
//     }
//     bc := &BitCombinations{k: k, n: n, m: m}
//     if err := bc.stringToBits(secretText); err != nil {
//         return nil, err
//     }
//     return bc, nil
// }
//
// func (bc *BitCombinations) stringToBits(secret string) error {
//     byteData := []byte(secret)
//     bc.secretBits = make([]int, 0)
//     for _, b := range byteData {
//         for i := 7; i >= 0; i-- {
//             bc.secretBits = append(bc.secretBits, int((b>>uint(i))&1))
//         }
//     }
//     bc.secretLen = len(bc.secretBits)
//     return nil
// }
//
// func bitsToString(bits []int) string {
//     if len(bits)%8 != 0 {
//         bits = bits[:len(bits)-(len(bits)%8)]
//     }
//     byteData := make([]byte, 0)
//     for i := 0; i < len(bits); i += 8 {
//         var val byte
//         for j := 0; j < 8; j++ {
//             val = (val << 1) | byte(bits[i+j])
//         }
//         byteData = append(byteData, val)
//     }
//     return string(byteData)
// }
//
// func (bc *BitCombinations) ShareGeneration() error {
//     // Generate random bits for first (k-1) shares
//     randomShares := make([][]int, bc.k-1)
//     for i := 0; i < bc.k-1; i++ {
//         randomShares[i] = make([]int, bc.secretLen)
//         for j := 0; j < bc.secretLen; j++ {
//             bit, _ := rand.Int(rand.Reader, big.NewInt(2))
//             randomShares[i][j] = int(bit.Int64())
//         }
//     }
//
//     // Last share = secret XOR (XOR of all random shares)
//     lastShare := make([]int, bc.secretLen)
//     copy(lastShare, bc.secretBits)
//     for _, rs := range randomShares {
//         for j := 0; j < bc.secretLen; j++ {
//             lastShare[j] ^= rs[j]
//         }
//     }
//
//     reconstructionShares := append(randomShares, lastShare)
//
//     // Create n shares
//     allShares := make([][]int, 0)
//     for i := 0; i < bc.m && i < len(reconstructionShares); i++ {
//         share := make([]int, bc.secretLen)
//         copy(share, reconstructionShares[i])
//         allShares = append(allShares, share)
//     }
//     for i := bc.m; i < len(reconstructionShares); i++ {
//         if len(allShares) < bc.n {
//             share := make([]int, bc.secretLen)
//             copy(share, reconstructionShares[i])
//             allShares = append(allShares, share)
//         }
//     }
//     for len(allShares) < bc.n {
//         dummy := make([]int, bc.secretLen)
//         for j := 0; j < bc.secretLen; j++ {
//             bit, _ := rand.Int(rand.Reader, big.NewInt(2))
//             dummy[j] = int(bit.Int64())
//         }
//         allShares = append(allShares, dummy)
//     }
//
//     bc.CombinedANDMask = allShares
//     return nil
// }
//
// func (bc *BitCombinations) ReconstructSecret(selectedShares [][]int) (string, error) {
//     if len(selectedShares) < bc.k {
//         return "", fmt.Errorf("need at least %d shares", bc.k)
//     }
//
//     minLen := len(selectedShares[0])
//     for _, s := range selectedShares {
//         if len(s) < minLen {
//             minLen = len(s)
//         }
//     }
//
//     result := make([]int, minLen)
//     copy(result, selectedShares[0][:minLen])
//     for i := 1; i < len(selectedShares); i++ {
//         for j := 0; j < minLen; j++ {
//             result[j] ^= selectedShares[i][j]
//         }
//     }
//
//     return bitsToString(result), nil
// }
//
// func (bc *BitCombinations) GetShares() [][]int {
//     return bc.CombinedANDMask
// }
//
// func CleanSecret(secret string) string {
//     parts := strings.SplitN(secret, ":", 4)
//     if len(parts) < 4 {
//         return secret
//     }
//
//     var length int
//     fmt.Sscanf(parts[1], "%d", &length)
//
//     totalLen := len(parts[2] + parts[3])
//     if totalLen > length {
//         excess := totalLen - length
//         if excess <= len(parts[3]) {
//             parts[3] = parts[3][:len(parts[3])-excess]
//         }
//     }
//
//     return fmt.Sprintf("%s:%s:%s:%s", parts[0], parts[1], parts[2], parts[3])
// }
//
// // ==================== Steganography ====================
//
// func EmbedShareInImage(shareBits []int, inputPath, outputPath string, isMandatory bool) error {
//     img, err := imaging.Open(inputPath)
//     if err != nil {
//         return err
//     }
//
//     bounds := img.Bounds()
//     flat := make([]uint8, 0)
//     for y := 0; y < bounds.Max.Y; y++ {
//         for x := 0; x < bounds.Max.X; x++ {
//             r, g, b, _ := img.At(x, y).RGBA()
//             flat = append(flat, uint8(r>>8), uint8(g>>8), uint8(b>>8))
//         }
//     }
//
//     // Header: mandatory flag (1) + length (32 bits)
//     header := make([]int, 0)
//     if isMandatory {
//         header = append(header, 1)
//     } else {
//         header = append(header, 0)
//     }
//
//     shareLen := len(shareBits)
//     for i := 31; i >= 0; i-- {
//         header = append(header, (shareLen>>uint(i))&1)
//     }
//
//     data := append(header, shareBits...)
//
//     if len(data) > len(flat) {
//         return fmt.Errorf("share too large for image")
//     }
//
//     for i, bit := range data {
//         if bit == 1 {
//             flat[i] = flat[i] | 1
//         } else {
//             flat[i] = flat[i] & 0xFE
//         }
//     }
//
//     newImg := imaging.New(bounds.Max.X, bounds.Max.Y, color.NRGBA{})
//     idx := 0
//     for y := 0; y < bounds.Max.Y; y++ {
//         for x := 0; x < bounds.Max.X; x++ {
//             newImg.SetNRGBA(x, y, color.NRGBA{R: flat[idx], G: flat[idx+1], B: flat[idx+2], A: 255})
//             idx += 3
//         }
//     }
//
//     out, err := os.Create(outputPath)
//     if err != nil {
//         return err
//     }
//     defer out.Close()
//     return png.Encode(out, newImg)
// }
//
// func ExtractShareFromImage(imagePath string) (bool, []int, error) {
//     img, err := imaging.Open(imagePath)
//     if err != nil {
//         return false, nil, err
//     }
//
//     bounds := img.Bounds()
//     flat := make([]uint8, 0)
//     for y := 0; y < bounds.Max.Y; y++ {
//         for x := 0; x < bounds.Max.X; x++ {
//             r, g, b, _ := img.At(x, y).RGBA()
//             flat = append(flat, uint8(r>>8), uint8(g>>8), uint8(b>>8))
//         }
//     }
//
//     flag := (flat[0] & 1) == 1
//
//     lengthBits := 0
//     for i := 1; i < 33; i++ {
//         lengthBits = (lengthBits << 1) | int(flat[i]&1)
//     }
//     shareLength := lengthBits
//
//     if shareLength > len(flat)-33 {
//         shareLength = len(flat) - 33
//     }
//
//     shareBits := make([]int, shareLength)
//     for i := 0; i < shareLength; i++ {
//         shareBits[i] = int(flat[33+i] & 1)
//     }
//
//     return flag, shareBits, nil
// }
//
// // ==================== Server ====================
//
// type Server struct {
//     router  *gin.Engine
//     uploads string
//     shares  string
// }
//
// func NewServer() *Server {
//     s := &Server{
//         router:  gin.Default(),
//         uploads: "uploads",
//         shares:  "shares",
//     }
//     os.MkdirAll(s.uploads, 0755)
//     os.MkdirAll(s.shares, 0755)
//     s.setupRoutes()
//     return s
// }
//
// func (s *Server) setupRoutes() {
//     s.router.Static("/static", "./static")
//     s.router.GET("/", func(c *gin.Context) {
//         c.File("./static/index.html")
//     })
//     s.router.POST("/api/generate", s.handleGenerate)
//     s.router.POST("/api/reconstruct", s.handleReconstruct)
//     s.router.GET("/api/download/:filename", s.handleDownload)
// }
//
// type GenerateRequest struct {
//     K       int    `json:"k"`
//     N       int    `json:"n"`
//     M       int    `json:"m"`
//     Secret  string `json:"secret"`
//     Cipher  string `json:"cipher"`
//     UseFile bool   `json:"useFile"`
// }
//
// type GenerateResponse struct {
//     Shares []struct {
//         ID        int    `json:"id"`
//         Mandatory bool   `json:"mandatory"`
//         URL       string `json:"url"`
//     } `json:"shares"`
// }
//
// func (s *Server) handleGenerate(c *gin.Context) {
//     var req GenerateRequest
//     if err := c.ShouldBindJSON(&req); err != nil {
//         c.JSON(400, gin.H{"error": err.Error()})
//         return
//     }
//
//     secret := req.Secret
//
//     // Choose cipher (using ChaCha20 for now, can be extended)
//     cipher := NewChaCha20Cipher()
//
//     // Build secret
//     cryptoLayer := NewCryptoLayer(cipher)
//     encryptedSecret, err := cryptoLayer.BuildSecretForSharing(secret)
//     if err != nil {
//         c.JSON(500, gin.H{"error": err.Error()})
//         return
//     }
//
//     // Generate shares
//     bc, err := NewBitCombinations(req.K, req.N, req.M, encryptedSecret)
//     if err != nil {
//         c.JSON(400, gin.H{"error": err.Error()})
//         return
//     }
//
//     if err := bc.ShareGeneration(); err != nil {
//         c.JSON(500, gin.H{"error": err.Error()})
//         return
//     }
//
//     shares := bc.GetShares()
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
//     response := GenerateResponse{}
//     for i, share := range shares {
//         isMandatory := i < req.M
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
//     c.JSON(200, response)
// }
//
// func (s *Server) handleReconstruct(c *gin.Context) {
//     // Get form values
//     kStr := c.PostForm("k")
//     mStr := c.PostForm("m")
//
//     k, _ := strconv.Atoi(kStr)
//     m, _ := strconv.Atoi(mStr)
//
//     // Get uploaded files
//     form, err := c.MultipartForm()
//     if err != nil {
//         c.JSON(400, gin.H{"error": err.Error()})
//         return
//     }
//
//     files := form.File["shares"]
//     if len(files) == 0 {
//         c.JSON(400, gin.H{"error": "No shares uploaded"})
//         return
//     }
//
//     // Extract shares from images
//     var mandatoryShares [][]int
//     var normalShares [][]int
//
//     for _, fileHeader := range files {
//         // Open the file
//         file, err := fileHeader.Open()
//         if err != nil {
//             c.JSON(500, gin.H{"error": err.Error()})
//             return
//         }
//
//         // Save temporarily
//         tmpPath := filepath.Join(s.uploads, fileHeader.Filename)
//         tmpFile, err := os.Create(tmpPath)
//         if err != nil {
//             file.Close()
//             c.JSON(500, gin.H{"error": err.Error()})
//             return
//         }
//         io.Copy(tmpFile, file)
//         tmpFile.Close()
//         file.Close()
//         defer os.Remove(tmpPath)
//
//         // Extract share
//         isMandatory, bits, err := ExtractShareFromImage(tmpPath)
//         if err != nil {
//             c.JSON(500, gin.H{"error": err.Error()})
//             return
//         }
//
//         if isMandatory {
//             mandatoryShares = append(mandatoryShares, bits)
//         } else {
//             normalShares = append(normalShares, bits)
//         }
//     }
//
//     // Check mandatory count
//     if len(mandatoryShares) < m {
//         c.JSON(400, gin.H{"error": fmt.Sprintf("Need %d mandatory shares, got %d", m, len(mandatoryShares))})
//         return
//     }
//
//     // Select shares for reconstruction
//     selected := mandatoryShares[:m]
//     remainingNeeded := k - m
//     if len(normalShares) < remainingNeeded {
//         c.JSON(400, gin.H{"error": fmt.Sprintf("Need %d more normal shares", remainingNeeded)})
//         return
//     }
//     selected = append(selected, normalShares[:remainingNeeded]...)
//
//     // Reconstruct
//     bc, _ := NewBitCombinations(k, 0, m, "")
//     secret, err := bc.ReconstructSecret(selected)
//     if err != nil {
//         c.JSON(500, gin.H{"error": err.Error()})
//         return
//     }
//
//     // Clean and decrypt
//     cleaned := CleanSecret(secret)
//     cipher := NewChaCha20Cipher()
//     cryptoLayer := NewCryptoLayer(cipher)
//     message, err := cryptoLayer.RecoverMessageFromSecret(cleaned)
//     if err != nil {
//         c.JSON(500, gin.H{"error": err.Error()})
//         return
//     }
//
//     c.JSON(200, gin.H{"secret": message})
// }
//
// func (s *Server) handleDownload(c *gin.Context) {
//     filename := c.Param("filename")
//     filepath := filepath.Join(s.shares, filename)
//
//     // Check if file exists
//     if _, err := os.Stat(filepath); os.IsNotExist(err) {
//         c.JSON(404, gin.H{"error": "File not found"})
//         return
//     }
//
//     c.File(filepath)
// }
//
// func (s *Server) createDefaultImage(path string) {
//     dir := filepath.Dir(path)
//     os.MkdirAll(dir, 0755)
//     img := imaging.New(800, 600, color.NRGBA{R: 128, G: 128, B: 128, A: 255})
//     err := imaging.Save(img, path)
//     if err != nil {
//         log.Printf("Failed to create default image: %v", err)
//     }
// }
//
// func (s *Server) Run(addr string) error {
//     return s.router.Run(addr)
// }
//
// func main() {
//     srv := NewServer()
//     log.Println("🚀 Server running on http://localhost:8080")
//     log.Println("📤 Generate shares with k,n,m parameters")
//     log.Println("🔓 Reconstruct with uploaded share images")
//     log.Fatal(srv.Run(":8080"))
// }
