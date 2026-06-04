## 2. Literature Review & Comparative Analysis
### 1. Shamir's Threshold Secret Sharing (1979)

Adi Shamir presented the basic (k,n) threshold scheme which is based on polynomial interpolation. A secret S is represented as the constant term of a random polynomial of degree k-1 over a finite field. Shares are given out as points (xi, yi) to n participants. To recover the secret we need any k points which we use to determine the polynomial via Lagrange interpolation and evaluate f(0)=S.

**Key Insight:** The scheme is of an information theoretic nature which means that with less than k shares you learn nothing of the secret. Each share is of the same size as the original secret.

**Drawbacks:** All shares have equal weight. We do not have a concept of primary or high value shares. If k=3 and n=5 any set of three shares will do; we do not put some shares forward as more important.

### 2. Visual Cryptography (Naor & Shamir, 1994)

Naor and Shamir extended the secret sharing with images, visual cryptography. They divided a binary image into n transparent shares. Where k shares are stacked, the human visual system receive the original image without any computation. Every shares appear as random noise.

**Key Insight:** Decryption is a no computation issue the human eye does the reconstruction. We put the shares into what appears to be random visual media.

**Limitations:** Shares are a visual of random patterns which do not at all pass for images. There is no set in which shares are. The reconstructed image goes out with less contrast and also lower resolution. Share size is the original image size times a factor that depends on k.

**Capacity Analysis:** In a (k,n) visual cryptography we see that each share is usually 2 to 4 times the size of the original image. If the original is 1 MB each share becomes 2 to 4 MB. The total distributed data is n x 2 to 4 MB which is a large storage overhead.

### 3. Shamir-based Distributed Storage with Erasure Coding (AWS S3 Model)

In today's cloud storage systems like Amazon S3 we see the use of erasure coding in combination with threshold principles for durability. Data is broken into n fragments with the use of Reed-Solomon codes which it turns out you only need any k of them for reconstruction. This is a shift from pure secret sharing which we do for storage efficiency instead of information-theoretic security.

**Working Principle:** An object of size S is broken into k data pieces of size S/k each. \(M = n - k\) parity fragments each of size S/k are computed. Total storage: \(n \times S/k = S \times n/k\). Any set of k fragments reconstruct the original.

### 4. Steganography-Based Secret Sharing (Lin & Tsai, 2004)

Lin and Tsai proposed embedding Shamir-generated shares to cover images using LSB (Least Significant Bits) steganography. They processed the secret image through Shamir's polynomial scheme to generate n shares, each share embedded into a different cover image by changing least significant bits.

**Key Insight:** This was one of the early works which combined cryptographic sharing with steganographic concealment, which in turn provided a double layer of protection: mathematical threshold security and visual undetectability.

**Approach:**
- Original secret: Image file
- Shares from Shamir's (k,n) scheme
- Each share embedded into a cover image
- Reconstruction: Extract steganographic images from k set, apply Lagrange interpolation

**Capacity Consideration:** For each share the secret is of the same size (Shamir property) and in LSB embedding we use 1 bit per pixel byte. A cover image of W x H pixels can fit W x H x 3 bits (RGB). For an \(800\times 600\) image: \(800\times 600\times 3 = 1,440,000\) bits which is 180 KB per share capacity.

**Limitations:** Classical Shamir sharing gives equal weight to all shares. No mandatory share enforcement. No encryption layer protecting the secret before sharing. Any set of k shares is sufficient.

### 5. The BNB Mandatory Share Scheme (Barman, Nandy, Biswas)

The BNB scheme puts a linear bounded algorithm which designates m out of n shares as mathematically mandatory. The scheme works with binary secret representations through the use of combinatorial mask matrices.

**Construction:**
- Produce all \(C(n, k-1)\) combinations of n bits with exactly \(k-1\) zeros.
- Create a mask matrix of width \(C(n, k-1) + m\).
- Fill first columns with combination patterns.
- Fill in the last few columns with identity-like patterns which have 1 in their column for mandatory share.
- Repeat masks to match secret length.
- Generate shares: Share = (Mask) AND (Secret Bits)
- Reconstruct: Recovered = (Share 1) OR (Share 2) OR ... OR (Share k)

**Capacity Analysis:** For L bits secret with parameters (k,n,m):

- Mask Width = \(C(n, k-1) + m\)
- Each Share size = L bits
- Expansion = 1:1

**Mandatory Property:** The last m columns make sure that if mandatory share i is absent then column of the mask contains all zeros, meaning those secret bits are permanently lost.

**Example:** For \((k = 3, n = 5, m = 2)\):
- \(5C2 = 10\) combinations
- Mask Width = \(10 + 2 = 12\)
- Secret of 1 MB = 8,388,608 bits requires 699,051 mask repetitions
- Each of 5 shares = 1 MB
- Any 3 shares including both mandatory shares can reconstruct the whole secret

### 2.6 Comparative Tables

| Feature | Shamir SSS | Visual Crypto | AWS Erasure | Lin & Tsai | BNB | This Work |
|---------|------------|---------------|-------------|------------|-----|-----------|
| Threshold (k,n) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Mandatory Shares | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ |
| Steganography | ✗ | Partial | ✗ | ✓ | ✗ | ✓ |
| Encryption | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Integrity Check | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ |
| Equal Share Size | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ |
| Share = Secret Size | ✓ | 2–4× | S/k | ✓ | ✓ | ✓ |

**Capacity Comparison** (1 MB secret image with parameters k = 5, n = 9)

| Approach | Shares | Size per Share | Total Storage | Reconstruction |
|----------|--------|----------------|---------------|----------------|
| Shamir SSS | 9 | 1 MB | 9 MB | Any 5 shares |
| Visual Crypto | 9 | 2–4 MB | 18–36 MB | Any 5 stacked |
| AWS Erasure | 9 | 0.2 MB | 1.8 MB | Any 5 fragments |
| Lin & Tsai | 9 | 1 MB (in cover) | Cover × 9 | Any 5 stego-images |
| BNB (raw) | 9 | 1 MB | 9 MB | 5 including mandatory |
| This Work | 9 | 1 MB (in cover) | Cover × 9 | 5 including mandatory |
