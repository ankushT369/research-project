## 5. Implementation
### Tech Stack & Environment

The project was built using Go 1.21+, since it gives a good balance between performance and readability. Development was done on Linux (Ubuntu 22.04), but it should also work on macOS and Windows since Go is cross-platform.

For dependencies, we used:
- **Gin** – lightweight HTTP server for the web interface
- **imaging** – for image processing like reading/writing PNGs and pixel manipulation
- **crypto libraries** – Go standard `crypto/rand` and `golang.org/x/crypto/chacha20poly1305`

There is no database or external service used. Everything runs in-memory and the shares are stored as image files on disk.

### Layer 1 – Encryption
We supported two encryption methods so that different approaches can be tested.

**ChaCha20-Poly1305** – This is the main encryption method. It generates a random 32-byte key and 12-byte nonce for every secret. Then authenticated encryption is applied to produce ciphertext. A SHA-256 hash of the original message is also added so integrity can be checked during decryption.

Basic flow:

```
FUNCTION Encrypt(plaintext):
    key = random 32 bytes
    nonce = random 12 bytes
    ciphertext = ChaCha20_Encrypt(key, nonce, plaintext)
    RETURN (key, nonce + ciphertext)
```

**Chaotic Logistic Map** – This is more experimental. It uses the logistic map equation \(x_{n+1} = r \cdot x_n \cdot (1 - x_n)\) with values of r chosen in the chaotic range (3.57 to 4.0). The seed works as the key and is used to generate a keystream by iterating the function and taking byte values. Then XOR is used for encryption. It is not as strong as ChaCha20, but it was implemented for experimentation and comparison.

Keystream generation:

```
FUNCTION generateKeystream(seed, length):
    x = map_seed_to_0.1_to_0.9(seed)
    r = 3.57 + (mod(seed * 1.7, 0.43))

    // warm up
    repeat 100 times:
        x = r * x * (1 - x)

    // generate bytes
    result = []
    repeat length times:
        x = r * x * (1 - x)
        result.append(byte(x * 256))

    return result
```

Both encryption methods finally output data in this format: `CIPHER_NAME:length:key_b64:ciphertext_b64`. This is then converted into bits for the secret sharing process.

### Layer 2 – BNB Secret Sharing
The BNB scheme works directly on bits. Three parameters are defined:
- n – total number of shares
- k – minimum shares required for reconstruction
- m – number of mandatory shares (all must be present)

**Share generation:** The secret string is first converted into bits. All combinations of choosing (k-1) shares out of n are generated. A mask matrix of size n × (C + m) is built, where C is the number of combinations. The first C columns contain unique patterns with exactly (k-1) zeros and the rest ones. The last m columns each have a single 1 in a unique mandatory share row. Each mask row is then tiled to match the length of the secret bits, and each share is computed as `mask_row AND secret_bits`.

**Reconstruction:** Any k shares that include all mandatory shares are taken, and a bitwise OR is performed. Due to the mask design, the OR recovers every 1 bit from the original secret.

**Mandatory Mask:**
```
1st Mandatory Mask: 000000000000000000011111111111111110000000000000
2nd Mandatory Mask: 0000000000111111111100000000000111110100000000000
3rd Mandatory Mask: 00001111110000001111000001111000010010000111111
1st Non-Mandatory Mask: 01110001110001110001000111000100100000111000111
2nd Non-Mandatory Mask: 101101100101100100100110010010001000001011011001
3rd Non-Mandatory Mask: 110110101010101001001010100100010000001101101010
4th Non-Mandatory Mask: 111011010011010010001101001001000000011101101100
```

**Mandatory Shares:**
```
1st Mandatory Share: 0000000000000000000000111011001001010000000000
2nd Mandatory Share: 0000000001001010110000000000100100000000000
3rd Mandatory Share: 000000110100000001100000001100000000010000110100
1st Non-Mandatory Share: 011100010100010100000001010000000100000101000100
2nd Non-Mandatory Share: 00110010010000010010001001000000000001001010000
3rd Non-Mandatory Share: 0101001001000001000010000100000000001101100000
4th Non-Mandatory Share: 011000010010010000000001001000100000001100110100
```

Simplified logic:

```
FUNCTION GenerateShares(secret_bits):
    combos = C(n, k-1)  // all combinations
    masks = empty_grid(n rows, combos_count + m columns)

    // fill combinations (which shares help reconstruct which positions)
    for each combo in combos:
        for each share in combo:
            masks[share][combo_index] = 1

    // mark mandatory shares (first m shares)
    for i = 0 to m-1:
        masks[i][combo_count + i] = 1

    // create each share by tiling mask and AND with secret
    shares = []
    for i = 0 to n-1:
        repeated_mask = repeat(masks[i], across full secret length)
        shares[i] = repeated_mask & secret_bits  // bitwise AND
    return shares
```

Reconstruction is simpler. It mainly ORs the share bits together. Because of the mask design, any bit present in at least k valid shares will reconstruct correctly.

### Layer 3 – Steganography
Each share is hidden inside PNG images using LSB (Least Significant Bit) technique.

The image pixels are flattened into bytes, where each pixel contributes RGB values. A small 33-bit header is added:
- 1 bit – mandatory flag
- 32 bits – length of share data

After that, actual share bits are embedded into the LSB of image bytes. This changes pixel values very slightly, so it is not noticeable visually. During extraction, the same process is reversed. First header is read, then share bits are extracted.

PNG format is used because it is lossless. JPEG is avoided since compression would destroy the hidden bits.

### Layer 4 – Web Server
The server exposes three main APIs:
- `POST /api/generate` – Takes inputs like k, n, m, secret message, cipher type, and optional image. It encrypts the secret, generates shares, embeds them into images, and returns downloadable share images.
- `POST /api/reconstruct` – Takes at least k share images and cipher type. It extracts bits, checks mandatory share condition, reconstructs the secret, and decrypts it.
- `GET /api/download/:filename` – Used to download generated share images.

A simple static frontend is also served for interaction.

### Challenges We Ran Into

- Bit padding issues while converting strings to bits, so we standardized 8-bit per byte handling.
- Image size limitation, since small images cannot store large shares.
- Combination generation was slow for large n, so we optimized it using iterative bit logic.
- Mandatory share check was missing initially and caused reconstruction failure in testing.

### Current Limitations

- Logistic map cipher is only for learning purpose, not production use.
- LSB method breaks if image is compressed or resized.
- JPEG format is not supported due to lossy compression.
