## 4. Designing Details & Flow Diagrams
So for the designing phase, we first thought about how the whole system will flow - like from encryption to share generation, then embedding and finally reconstruction. Actually we started with drawing some rough diagrams on paper but then later we moved to Mermaid because it's easier to edit and also looks cleaner in the report.

The main challenge was to decide how the BNB secret sharing scheme will work with the mandatory shares concept. Because the original paper didn't really talk about mandatory shares that much. So we had to design our own logic for the mandatory flag and also figure out how to embed that flag inside the image header. One mistake we did was we first tried to store the mandatory flag separate from the share bits. But then we realised it's better to put it in the LSB of the first pixel itself. That way extraction is simpler.

For the chaos cipher, we spent a lot of time designing the logistic map parameters. If you choose wrong r value the keystream becomes periodic which is bad for security. Our supervisor told us to use r between 3.57 and 4.0 and we did that. But still we had to test many seeds because some values still gave poor randomness. Honestly it was trial and error.

The web interface design was also a thing. We wanted it to be simple so that any user can upload images and get shares without knowing the technical details. But we faced problem with file upload size because large images take time to process. So we added a check that the image must be at least 800x600. That gave us enough capacity without being too slow.

Another design decision was to use PNG instead of JPEG. LSB embedding works better with lossless formats - actually we learned this the hard way after JPEG compressed our bits and the reconstruction failed. So PNG it is.

The overall design was not finalised in one go. We changed many things like the header length from 16 bits to 32 bits after we saw that some encrypted secrets were longer than expected. So the designing part was more about trial and error than following a fixed plan.


### Layer 1: Encryption Layer

### Layer 2: BNB Secret Sharing

### Layer 3: Embedding (Steganography)

### Layer 4: Extraction (Reconstruction Phase)

### Layer 5: Reconstruction & Decryption
