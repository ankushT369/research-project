from secret_scheme import CryptoLayer, BitCombinations

def main():
    original_message = "this is my super secret message"

    crypto = CryptoLayer()

    M_prime = crypto.build_secret_for_sharing(original_message)
    print("M' (for sharing):", M_prime)

    combo = BitCombinations(k=5, n=7, m=3, sec_txt=M_prime)
    combo.share_generation()

    reconstructed_M_prime = combo.reconstruct_secret()
    print("\nReconstructed M':", reconstructed_M_prime)

    # Ensure bit-perfect recovery at this layer
    if M_prime != reconstructed_M_prime:
        print("\n[WARNING] M' and reconstructed M' differ!")
    else:
        print("\n[OK] M' reconstructed exactly.")

    recovered_message = crypto.recover_message_from_secret(reconstructed_M_prime)
    print("\nRecovered original message:", recovered_message)


if __name__ == "__main__":
    main()
