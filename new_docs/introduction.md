## 1. Introduction
### 1.1 Motivation

The single point of failure can makes it easy to lose sensitive information if the encryption key has been lost, therefore it can directly compromise the security of sensitive data. In addition to losing security through a breach, privy possessors ability to share sensitive data will also be undermined. There are several ways that secret sharing can be implemented by allocating trust to several different individuals. Shamir's \((k,n)\) secret sharing method produces n shares, and any k of those shares can reconstruct the original secret. However, this technique makes several assumptions about how parties will behave equally; they will likely not behave equally.

Weighted and multi-level methods address this problem, but they will typically take a longer time to compute or otherwise produce many more bits per share of information. The BNB scheme is the best solution because it provides a pre-determined quantity of shares using combinatorial masking for reconstruction, and it is still utilizing a cryptographic-based design.

In order to solve these issues, we will incorporate steganography into the sharing process and create an innocuous image to hide individual shares.

### 1.2 Problem Statement

Current secret sharing methods have some limitations. Most traditional schemes treat all shares equally and do not provide any hierarchy between participants. Also, when shares are stored in binary or hexadecimal form, they can leave visible artifacts which may attract unwanted attention. Another issue is that many methods do not provide a proper way to verify whether a share has been modified or tampered with.

To solve these problems, the proposed system uses the BNB protocol with mandated shares, hides the shares inside images using steganography, and applies authenticated encryption with integrity verification to make the sharing process more secure and reliable.

### 1.3 Aim & Objective

**Aim:** Our main aim is to to create and confirm a priority based secure secret sharing system that combines mandatory BNB sharing and image steganography.

**Objective:** To develop, implement and validate a prioritized secure secret sharing mechanism by integrating BNB mandatory shares along with steganographic techniques.

1. Implement the BNB combinatorial technique for (k,n,m) schemes having m as mandatory shares.
2. Implemented cryptographic algorithm using ChaCha20 and Chaos-based algorithm, also ensured the SHA-256 hash based integrity.
3. Implementation of steganographic encoding/decoding to embed the shares into PNG images.
4. Develop a web interface for generation of shares from text/files and optional custom carrier images.
5. Validation of system for different parameters.
6. Analysis of security issues such as brute force and steganographic detection attacks.

### 1.4 Scope

**In-Scope:**
- We have used BNB algorithm to determine how to break up secrets into their binary components.
- ChaCha20-Poly1305 authentication method that uses random keys.
- Steganographic LSB embedding process for PNG files using a 33 bit self-descriptive header.
- Web interface and RESTful API endpoint will allow users to upload carrier images automatically and retrieve any default data.
- When inputting a secret in text or file format, the secret is automatically reconstructed after the user has completed downloading it.

**Out-of-Scope:**
- Audio or video as the carrier of the hidden information.
- Robustness against compression and/or transformation of hidden data.
- Use of a network-based system to store the shares of hidden information.
- Web interface authentication.
- Other encryption methods besides ChaCha20-Poly1305.
- Security analysis references (no proofs).

### 1.5 Requirements

Requirements:
- The maximum possible length of the secret will depend on the resolution (image width and aspect ratio (image height) of the carrier image's resolution (Image width, image height, and 3 bits).
- The shares will have to be generated serverside because the secret will require k and m to reconstruct.
- The carrier default resolution will be set to \(800 \times 600\) pixels (approximately 180 KB of capacity).
