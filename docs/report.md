# Introduction
## Motivation
The single point of failure can makes it easy to lose sensitive information if the encryption key has been lost, therefore it can directly compromise the security of sensitive data. In addition to losing security through a breach, privy possessor's ability to share sensitive data will also be undermined. There are several ways that secret sharing can be implemented by allocating trust to several different individuals. Shamir’s (k,n) secret sharing method produces n shares, and any k of those shares can reconstruct the original secret. However, this technique makes several assumptions about how parties will behave equally; they will likely not behave equally.

Weighted and multi-level methods address this problem, but they will typically take a longer time to compute or otherwise produce many more bits per share of information. The BNB scheme is the best solution because it provides a pre-determined quantity of shares using combinatorial masking for reconstruction, and it is still utilizing a cryptographic-based design.

In order to solve these issues, we will incorporate steganography into the sharing process and create an innocuous image to hide individual shares.

## Problem Statement
Current secret sharing methods have some limitations. Most traditional schemes treat all shares equally and do not provide any hierarchy between participants. Also, when shares are stored in binary or hexadecimal form, they can leave visible artifacts which may attract unwanted attention. Another issue is that many methods do not provide a proper way to verify whether a share has been modified or tampered with.

To solve these problems, the proposed system uses the BNB protocol with mandated shares, hides the shares inside images using steganography, and applies authenticated encryption with integrity verification to make the sharing process more secure and reliable.

## Aim & Objective
Aim: Our main aim is to to **create** and **confirm** a priority based secure secret sharing system **that** **combines** mandatory **BNB** **sharing** **and** image steganography.

Objective: To develop, implement and validate a prioritized secure secret sharing mechanism by integrating BNB mandatory shares along with steganographic techniques.

Goals:
1. Implement the BNB combinatorial technique for (k,n,m) schemes having m as mandatory shares.
2. Implementd cryptographic algorithm using ChaCha20 and Chaos-based algorithm, also ensured the SHA-256 hash based integrity.
3. Implementation of steganographic encoding/decoding to embed the shares into PNG images.
4. Develop a web interface for generation of shares from text/files and optional custom carrier images.
5. Validation of system for different parameters.
6. Analysis of security issues such as brute force and steganographic detection attacks.

## Scope
### In-Scope:
- We have used **BNB** algorithm to determine how to break up secrets into their binary components.
- **ChaCha20-Poly1305** authentication method that uses random keys
- Steganographic LSB embedding process for PNG files using a 33 bit self-descriptive header.
- Web interface and RESTful API endpoint will allow users to upload carrier images automatically and retrieve any default data.
- When inputting a secret in text or file format, the secret is automatically reconstructed after the user has completed downloading it.

### Out-of-Scope:
Here are some of the criteria to consider when designing an audio/video steganography system:
- Audio or video as the carrier of the hidden information
- Robustness against compression and/or transformation of hidden data
- Use of a network-based system to store the shares of hidden information
- Web interface authentication
- Other encryption methods besides **ChaCha20-Poly1305**
- Security analysis references (no proofs).
### Requirements:
- The** **maximum** **possible** **length** **of the secret** **will** **depend** **on** **the resolution (image width)** **and aspect ratio (image height) of the carrier image's resolution (Imagewidth, imageheight, and 3 bits).
- The shares will have to be generated serverside because** **the** **secret** **will** **require k and m to** **reconstruct.
- The** **carrier** **default** **resolution** **will be set to 800×600 pixels** (**approximately 180 KB of capacity).

# Project Planning
The project was started by dividing the group members based on their strengths. After that, research was done on different encryption algorithms such as AES, ChaCha20, and chaos-based algorithms. The chaos-based algorithm was an important part of the project because it can help in balancing both security and speed.

After researching many algorithms, it was decided that the implementation should be flexible so that different algorithms can be chosen according to the requirment. Then, research papers of the BNB secret sharing algorithm were studied to understand their working and linear approach.

Based on the research papers, the foundation of the project was designed and implemented. Since this foundation is the main part on which the whole project works, extra focus was given to understand and implement it properly.

After completing the foundation a networking layer was built using Go. The Gin framework was used to create the server on top of it, and the frontend was also developed alongside it. Finally, the complete system was deployed on AWS for integrity testing and to check the overall working of the project. This helpd in verifying that all components  were working together correctly.

# Implementation
### Tech Stack & Environment
The project was built using Go 1.21+, since it gives a good balance between performance and readability. Development was done on Linux (Ubuntu 22.04), but it should also work on macOS and Windows since Go is cross-platform.

For dependencies, we used:

* Gin – lightweight HTTP server for the web interface
* imaging – for image processing like reading/writing PNGs and pixel manipulation
* crypto libraries – Go standard `crypto/rand` and `golang.org/x/crypto/chacha20poly1305`

There is no database or external service used. Everything runs in-memory and the shares are stored as image files on disk.

### Layer 1 – Encryption
We supported two encryption methods so that different approaches can be tested.

**ChaCha20-Poly1305** – This is the main encryption method. It generates a random 32-byte key and 12-byte nonce for every secret. Then authenticated encryption is applied to produce ciphertext. A SHA-256 hash of the original message is also added so integrity can be checked during decryption.

Basic flow looks like this:

```go
func (c *ChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, []byte, error) {
    key := make([]byte, 32)
    nonce := make([]byte, 12)
    aead, _ := chacha20poly1305.New(key)
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)
    return key, append(nonce, ciphertext...), nil
}
```

**Chaotic Logistic Map** – This is more experimental. It uses the logistic map equation `x = r * x * (1 - x)` with values of r chosen in the chaotic range (3.57 to 4.0). The seed works as the key and is used to generate a keystream by iterating the function and taking byte values. Then XOR is used for encryption. It is not as strong as ChaCha20, but it was implemented for experimentation and comparison.

Keystream generation is the main part:

```go
func (c *LogisticChaosCipher) generateKeystream(seed []byte, length int) []byte {
    x := normalize(seed)
    r := 3.57 + (seedVal * 1.7 % 0.43)

    for i := 0; i < 100; i++ {
        x = r * x * (1 - x)
    }

    keystream := make([]byte, length)
    for i := 0; i < length; i++ {
        x = r * x * (1 - x)
        keystream[i] = byte(x * 256)
    }
    return keystream
}
```

Both encryption methods finally output data in this format:
`CIPHER_NAME:length:key_b64:ciphertext_b64`
This is then converted into bits for the secret sharing process.

### Layer 2 – BNB Secret Sharing
The BNB scheme works on bits instead of numbers.

We define `n` total shares, `k` required shares for reconstruction, and `m` mandatory shares.

For every bit position in the secret, a mask matrix is created. Each share gets a row from this mask and is ANDed with the secret bits.

The idea is based on generating combinations of `(k-1)` shares out of `n`, along with mandatory constraints. This ensures:

* Without at least `k` shares, reconstruction is not possible
* Without all `m` mandatory shares, reconstruction also fails

The same mask pattern is repeated across the full bit length so it works for longer inputs.

Simplified logic:

```go
func (bnb *BNBSecretSharing) GenerateShares(secretBits []int) ([][]int, error) {
    combinations := generateCombinations(bnb.n, bnb.k-1)
    masks := make([][]int, bnb.n)

    for col, combo := range combinations {
        for _, row := range combo {
            masks[row][col] = 1
        }
    }

    for i := 0; i < bnb.m; i++ {
        masks[i][len(combinations)+i] = 1
    }

    shares := make([][]int, bnb.n)
    for i := 0; i < bnb.n; i++ {
        shares[i] = andBits(tileMask(masks[i], len(secretBits)), secretBits)
    }

    return shares, nil
}
```

Reconstruction is simpler. It mainly ORs the share bits together. Because of the mask design, any bit present in at least `k` valid shares will reconstruct correctly.

### Layer 3 – Steganography
Each share is hidden inside PNG images using LSB (Least Significant Bit) technique.

The image pixels are flattened into bytes, where each pixel contributes RGB values.

A small 33-bit header is added:

* 1 bit – mandatory flag
* 32 bits – length of share data

After that, actual share bits are embedded into the LSB of image bytes. This changes pixel values very slightly, so it is not noticeable visually.

During extraction, the same process is reversed. First header is read, then share bits are extracted.

PNG format is used because it is lossless. JPEG is avoided since compression would destroy the hidden bits.

### Layer 4 – Web Server
The server exposes three main APIs:

**POST /api/generate** – Takes inputs like k, n, m, secret message, cipher type, and optional image. It encrypts the secret, generates shares, embeds them into images, and returns downloadable share images.

**POST /api/reconstruct** – Takes at least k share images and cipher type. It extracts bits, checks mandatory share condition, reconstructs the secret, and decrypts it.

**GET /api/download/:filename** – Used to download generated share images.
A simple static frontend is also served for interaction.

### Challenges We Ran Into
- Bit padding issues while converting strings to bits, so we standardized 8-bit per byte handling
- Image size limitation, since small images cannot store large shares
- Combination generation was slow for large n, so we optimized it using iterative bit logic
- Mandatory share check was missing initially and caused reconstruction failure in testing

### Testing Approach
Testing started with small values like (k=2, n=3, m=1) using simple messages like “hello”, then scaled up to larger configurations like (k=5, n=10, m=3).

We verified:

- Reconstruction works when threshold is met
- Fails when fewer than k shares are used
- Fails if mandatory shares are missing
- Chaos cipher works only when same seed is used

### Current Limitations
- Logistic map cipher is only for learning purpose, not production use
- LSB method breaks if image is compressed or resized
- JPEG format is not supported due to lossy compression
