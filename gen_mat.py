n = 7
k = 5
total_bits = n
ones = k - 1

x = (1 << ones) - 1
limit = 1 << total_bits

count = 0

print(f"All {total_bits}-bit numbers with {ones} ones:\n")

while x < limit:
    print(f"{x:>3}  ->  {x:0{total_bits}b}")
    count += 1
    c = x & -x
    r = x + c
    x = (((r ^ x) >> 2) // c) | r

print(f"\nGenerated {count} numbers with {k} ones")

