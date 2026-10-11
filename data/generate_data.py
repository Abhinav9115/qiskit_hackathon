import os
import hashlib

def generate_deterministic_file(path, size_bytes, seed):
    chunk_size = 65536
    written = 0
    cur = hashlib.sha256(seed).digest()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        while written < size_bytes:
            to_write = min(chunk_size, size_bytes - written)
            buf = bytearray()
            while len(buf) < to_write:
                cur = hashlib.sha256(cur).digest()
                buf.extend(cur)
            f.write(buf[:to_write])
            written += to_write
    with open(path, "rb") as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"Created {path}: {written} bytes, SHA256: {file_hash}")

if __name__ == "__main__":
    generate_deterministic_file("data/raw/payload_1kb.bin", 1024, b"QSC-1KB-SEED")
    generate_deterministic_file("data/raw/payload_100kb.bin", 102400, b"QSC-100KB-SEED")
    generate_deterministic_file("data/raw/payload_10mb.bin", 10485760, b"QSC-10MB-SEED")
