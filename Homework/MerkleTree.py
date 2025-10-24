# merkle_simple.py
# Simple Merkle tree with proof generation and verification
import hashlib

def h(x: bytes) -> str:
    """Return sha256 hex digest of bytes."""
    return hashlib.sha256(x).hexdigest()

def build_tree(values):
    """Build layers from leaves up. Values: list of strings.
       Returns layers where layers[0] are leaves (hex), last layer is root (single hex)."""
    leaves = [h(v.encode()) for v in values]
    if not leaves:
        return [[""]]  # empty placeholder
    layers = [leaves]
    while len(layers[-1]) > 1:
        cur = layers[-1]
        nxt = []
        i = 0
        while i < len(cur):
            left = cur[i]
            right = cur[i+1] if i+1 < len(cur) else cur[i]  # duplicate last if odd
            nxt.append(h((left + right).encode()))
            i += 2
        layers.append(nxt)
    return layers

def root(layers):
    return layers[-1][0] if layers and layers[-1] else ""

def get_proof(layers, index):
    """Return proof for leaf index (0-based) as list of tuples (direction, sibling_hex).
       direction = 'L' if sibling is left of node, 'R' if sibling is right of node."""
    proof = []
    idx = index
    if index < 0 or index >= len(layers[0]):
        return None
    for level in range(len(layers)-1):
        layer = layers[level]
        pair = idx ^ 1  # sibling index
        if pair >= len(layer):
            sibling = layer[idx]  # duplicated sibling
        else:
            sibling = layer[pair]
        direction = 'L' if pair < idx else 'R'
        proof.append((direction, sibling))
        idx //= 2
    return proof

def verify_proof(value, proof, expected_root):
    cur = h(value.encode())
    for direction, sibling in proof:
        if direction == 'L':
            cur = h((sibling + cur).encode())
        else:
            cur = h((cur + sibling).encode())
    return cur == expected_root

def main():
    print("Simple Merkle Tree (interactive)")
    n = int(input("Number of values: ").strip())
    values = []
    for i in range(n):
        values.append(input(f"Value #{i+1}: ").strip())
    layers = build_tree(values)
    r = root(layers)
    print("\nRoot hash:", r)
    q = int(input("\nNumber of queries: ").strip())
    for qi in range(q):
        token = input(f"\nQuery #{qi+1} (enter 1-based index or exact value): ").strip()
        # try parse as 1-based index
        idx = None
        try:
            idx0 = int(token) - 1
            if 0 <= idx0 < len(values):
                idx = idx0
        except ValueError:
            # treat token as value: find first occurrence
            try:
                idx = values.index(token)
            except ValueError:
                idx = None
        if idx is None:
            print("NOTFOUND")
            continue
        proof = get_proof(layers, idx)
        print("PROOF length:", len(proof))
        for d, s in proof:
            print(d, s)
        # show verification quick-check
        ok = verify_proof(values[idx], proof, r)
        print("Verification:", "OK" if ok else "FAIL")

if __name__ == "__main__":
    # Example-run guidance if you prefer to paste one block:
    # Example input to paste in PyCharm console when prompted:
    # Number of values: 4
    # Value #1: a
    # Value #2: b
    # Value #3: c
    # Value #4: d
    # Number of queries: 2
    # Query #1 (enter 1-based index or exact value): 2
    # Query #2 (enter 1-based index or exact value): c
    main()