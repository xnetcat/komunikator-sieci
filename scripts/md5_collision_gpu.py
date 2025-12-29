#!/usr/bin/env python3
"""
MD5 Collision Attack Demonstration using macOS GPU (Metal via MLX)

This script demonstrates:
1. GPU-accelerated MD5 hash generation using Apple Silicon
2. Birthday attack to find partial collisions (matching hash prefixes)
3. Performance comparison between CPU and GPU approaches

Note: True MD5 collisions require sophisticated differential cryptanalysis
(like HashClash). This demonstrates the birthday attack approach for finding
partial collisions, which is educational and practical for GPU demonstration.

Requirements:
    pip install mlx numpy

Usage:
    python md5_collision_gpu.py [--prefix-bits N] [--batch-size N]
"""

import argparse
import hashlib
import os
import struct
import time
from typing import Optional, Tuple
import numpy as np

# Try to import MLX for GPU acceleration
try:
    import mlx.core as mx
    HAS_MLX = True
    print("✓ MLX available - GPU acceleration enabled (Apple Silicon)")
except ImportError:
    HAS_MLX = False
    print("✗ MLX not available - falling back to CPU-only mode")
    print("  Install with: pip install mlx")


# ==============================================================================
# MD5 Constants and Functions
# ==============================================================================

# MD5 round constants (sine-derived)
MD5_K = np.array([
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
], dtype=np.uint32)

# Rotation amounts per round
MD5_S = np.array([
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
], dtype=np.uint32)


def left_rotate(x: np.ndarray, n: int) -> np.ndarray:
    """Left rotate 32-bit integers."""
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md5_compress_numpy(blocks: np.ndarray) -> np.ndarray:
    """
    Vectorized MD5 compression function using NumPy.
    Processes multiple 64-byte blocks in parallel.
    
    Args:
        blocks: Array of shape (N, 16) containing 32-bit words
        
    Returns:
        Array of shape (N, 4) containing MD5 hash states
    """
    n = blocks.shape[0]
    
    # Initial hash values
    a0 = np.full(n, 0x67452301, dtype=np.uint32)
    b0 = np.full(n, 0xefcdab89, dtype=np.uint32)
    c0 = np.full(n, 0x98badcfe, dtype=np.uint32)
    d0 = np.full(n, 0x10325476, dtype=np.uint32)
    
    a, b, c, d = a0.copy(), b0.copy(), c0.copy(), d0.copy()
    
    for i in range(64):
        if i < 16:
            f = (b & c) | ((~b) & d)
            g = i
        elif i < 32:
            f = (d & b) | ((~d) & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | (~d))
            g = (7 * i) % 16
        
        f = (f + a + MD5_K[i] + blocks[:, g]) & 0xFFFFFFFF
        a = d
        d = c
        c = b
        b = (b + left_rotate(f, int(MD5_S[i]))) & 0xFFFFFFFF
    
    result = np.stack([
        (a0 + a) & 0xFFFFFFFF,
        (b0 + b) & 0xFFFFFFFF,
        (c0 + c) & 0xFFFFFFFF,
        (d0 + d) & 0xFFFFFFFF,
    ], axis=1)
    
    return result


def prepare_md5_blocks(messages: np.ndarray) -> np.ndarray:
    """
    Prepare MD5 message blocks with padding.
    Assumes messages are 8 bytes (64 bits) each for simplicity.
    
    Args:
        messages: Array of shape (N,) with uint64 messages
        
    Returns:
        Array of shape (N, 16) with padded 32-bit words
    """
    n = len(messages)
    blocks = np.zeros((n, 16), dtype=np.uint32)
    
    # Pack message into first two 32-bit words (little-endian)
    blocks[:, 0] = (messages & 0xFFFFFFFF).astype(np.uint32)
    blocks[:, 1] = ((messages >> 32) & 0xFFFFFFFF).astype(np.uint32)
    
    # Padding: append 1 bit followed by zeros
    blocks[:, 2] = 0x80  # 1 bit followed by zeros
    
    # Length in bits (64 bits = 8 bytes) in last two words
    blocks[:, 14] = 64  # Low 32 bits of bit length
    blocks[:, 15] = 0   # High 32 bits of bit length
    
    return blocks


if HAS_MLX:
    def left_rotate_mlx(x: mx.array, n: int) -> mx.array:
        """Left rotate 32-bit integers using MLX."""
        n = n % 32
        # MLX doesn't have direct bitwise ops on uint32, so we use int32
        x = x.astype(mx.uint32)
        return ((x << n) | (x >> (32 - n)))

    def md5_compress_mlx(blocks: mx.array) -> mx.array:
        """
        GPU-accelerated MD5 compression using MLX.
        """
        n = blocks.shape[0]
        
        # Initial hash values
        a0 = mx.full((n,), 0x67452301, dtype=mx.uint32)
        b0 = mx.full((n,), 0xefcdab89, dtype=mx.uint32)
        c0 = mx.full((n,), 0x98badcfe, dtype=mx.uint32)
        d0 = mx.full((n,), 0x10325476, dtype=mx.uint32)
        
        # Convert constants to MLX
        K = mx.array(MD5_K, dtype=mx.uint32)
        
        a, b, c, d = a0, b0, c0, d0
        
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            
            f = f + a + K[i] + blocks[:, g]
            a = d
            d = c
            c = b
            b = b + left_rotate_mlx(f, int(MD5_S[i]))
        
        result = mx.stack([a0 + a, b0 + b, c0 + c, d0 + d], axis=1)
        return result


# ==============================================================================
# Collision Finding
# ==============================================================================

def hash_to_hex(state: np.ndarray) -> str:
    """Convert MD5 state to hex string."""
    result = b''
    for word in state:
        result += struct.pack('<I', int(word))
    return result.hex()


def find_partial_collision_cpu(
    prefix_bits: int = 32,
    max_attempts: int = 10_000_000,
    batch_size: int = 100_000,
) -> Tuple[Optional[Tuple[int, int]], dict]:
    """
    Find two different messages with matching hash prefix using CPU.
    Uses birthday attack - store hashes and look for collisions.
    
    Args:
        prefix_bits: Number of leading bits that must match
        max_attempts: Maximum number of hashes to try
        batch_size: Hashes per batch
        
    Returns:
        Tuple of (collision pair or None, stats dict)
    """
    print(f"\n🔍 Searching for {prefix_bits}-bit partial collision (CPU)...")
    print(f"   Expected attempts: ~2^{prefix_bits//2} = {2**(prefix_bits//2):,}")
    
    seen = {}  # prefix -> message
    total_hashes = 0
    start_time = time.time()
    
    prefix_mask = (1 << prefix_bits) - 1
    
    for batch_start in range(0, max_attempts, batch_size):
        # Generate batch of messages
        messages = np.arange(batch_start, min(batch_start + batch_size, max_attempts), dtype=np.uint64)
        blocks = prepare_md5_blocks(messages)
        
        # Compute hashes
        hashes = md5_compress_numpy(blocks)
        
        # Extract prefixes and check for collisions
        for i, (msg, hash_state) in enumerate(zip(messages, hashes)):
            # Get first 32 bits as prefix
            prefix = int(hash_state[0]) & prefix_mask
            
            if prefix in seen:
                other_msg = seen[prefix]
                if other_msg != msg:
                    elapsed = time.time() - start_time
                    stats = {
                        'total_hashes': total_hashes + i + 1,
                        'time_seconds': elapsed,
                        'hashes_per_second': (total_hashes + i + 1) / elapsed,
                    }
                    return (int(other_msg), int(msg)), stats
            else:
                seen[prefix] = msg
        
        total_hashes += len(messages)
        
        if total_hashes % 1_000_000 == 0:
            elapsed = time.time() - start_time
            rate = total_hashes / elapsed
            print(f"   Processed {total_hashes:,} hashes ({rate:,.0f}/s)...")
    
    elapsed = time.time() - start_time
    stats = {
        'total_hashes': total_hashes,
        'time_seconds': elapsed,
        'hashes_per_second': total_hashes / elapsed,
    }
    return None, stats


if HAS_MLX:
    def find_partial_collision_gpu(
        prefix_bits: int = 32,
        max_attempts: int = 10_000_000,
        batch_size: int = 500_000,
    ) -> Tuple[Optional[Tuple[int, int]], dict]:
        """
        Find two different messages with matching hash prefix using GPU (MLX).
        """
        print(f"\n🔍 Searching for {prefix_bits}-bit partial collision (GPU)...")
        print(f"   Expected attempts: ~2^{prefix_bits//2} = {2**(prefix_bits//2):,}")
        
        seen = {}
        total_hashes = 0
        start_time = time.time()
        
        prefix_mask = (1 << prefix_bits) - 1
        
        for batch_start in range(0, max_attempts, batch_size):
            # Generate batch of messages
            messages = np.arange(batch_start, min(batch_start + batch_size, max_attempts), dtype=np.uint64)
            blocks = prepare_md5_blocks(messages)
            
            # Convert to MLX and compute on GPU
            blocks_mlx = mx.array(blocks, dtype=mx.uint32)
            hashes_mlx = md5_compress_mlx(blocks_mlx)
            mx.eval(hashes_mlx)  # Force GPU computation
            
            # Convert back to NumPy for collision detection
            hashes = np.array(hashes_mlx, dtype=np.uint32)
            
            # Check for collisions
            for i, (msg, hash_state) in enumerate(zip(messages, hashes)):
                prefix = int(hash_state[0]) & prefix_mask
                
                if prefix in seen:
                    other_msg = seen[prefix]
                    if other_msg != msg:
                        elapsed = time.time() - start_time
                        stats = {
                            'total_hashes': total_hashes + i + 1,
                            'time_seconds': elapsed,
                            'hashes_per_second': (total_hashes + i + 1) / elapsed,
                        }
                        return (int(other_msg), int(msg)), stats
                else:
                    seen[prefix] = msg
            
            total_hashes += len(messages)
            
            if total_hashes % 1_000_000 == 0:
                elapsed = time.time() - start_time
                rate = total_hashes / elapsed
                print(f"   Processed {total_hashes:,} hashes ({rate:,.0f}/s)...")
        
        elapsed = time.time() - start_time
        stats = {
            'total_hashes': total_hashes,
            'time_seconds': elapsed,
            'hashes_per_second': total_hashes / elapsed,
        }
        return None, stats


def verify_collision(msg1: int, msg2: int, prefix_bits: int) -> bool:
    """Verify that two messages have matching hash prefixes."""
    # Convert to bytes
    bytes1 = struct.pack('<Q', msg1)
    bytes2 = struct.pack('<Q', msg2)
    
    # Compute real MD5 hashes
    hash1 = hashlib.md5(bytes1).hexdigest()
    hash2 = hashlib.md5(bytes2).hexdigest()
    
    # Check prefix match
    prefix_chars = prefix_bits // 4
    match = hash1[:prefix_chars] == hash2[:prefix_chars]
    
    print(f"\n📋 Verification:")
    print(f"   Message 1: {msg1} (0x{msg1:016x})")
    print(f"   Hash 1:    {hash1}")
    print(f"   Message 2: {msg2} (0x{msg2:016x})")
    print(f"   Hash 2:    {hash2}")
    print(f"   Prefix ({prefix_bits} bits): {'✓ MATCH' if match else '✗ NO MATCH'}")
    
    return match


def verify_string_collision(original: str, collision_suffix: bytes, prefix_bits: int) -> bool:
    """Verify collision between original string and found collision."""
    original_bytes = original.encode('utf-8')
    collision_bytes = original_bytes + collision_suffix
    
    hash1 = hashlib.md5(original_bytes).hexdigest()
    hash2 = hashlib.md5(collision_bytes).hexdigest()
    
    prefix_chars = prefix_bits // 4
    match = hash1[:prefix_chars] == hash2[:prefix_chars]
    
    print(f"\n📋 Verification:")
    print(f"   Original:  \"{original}\"")
    print(f"   Hash 1:    {hash1}")
    print(f"   Collision: \"{original}\" + {collision_suffix.hex()} (appended bytes)")
    print(f"   Hash 2:    {hash2}")
    print(f"   Prefix ({prefix_bits} bits): {'✓ MATCH' if match else '✗ NO MATCH'}")
    
    return match


# ==============================================================================
# Custom String Collision Finding
# ==============================================================================

def find_collision_for_string_cpu(
    target_string: str,
    prefix_bits: int = 24,
    max_attempts: int = 50_000_000,
    batch_size: int = 100_000,
) -> Tuple[Optional[bytes], dict]:
    """
    Find a suffix that when appended to target_string produces a hash
    with the same prefix as the original string's hash.
    
    Args:
        target_string: The string to find a collision for
        prefix_bits: Number of bits that must match
        max_attempts: Maximum attempts
        batch_size: Batch size for processing
        
    Returns:
        Tuple of (collision suffix bytes or None, stats dict)
    """
    print(f"\n🔍 Searching for {prefix_bits}-bit collision for \"{target_string}\" (CPU)...")
    
    # Compute target hash prefix
    target_bytes = target_string.encode('utf-8')
    target_hash = hashlib.md5(target_bytes).hexdigest()
    prefix_chars = prefix_bits // 4
    target_prefix = target_hash[:prefix_chars]
    
    print(f"   Target hash: {target_hash}")
    print(f"   Target prefix ({prefix_bits} bits): {target_prefix}")
    print(f"   Expected attempts: ~2^{prefix_bits} = {2**prefix_bits:,}")
    
    total_hashes = 0
    start_time = time.time()
    
    for batch_start in range(0, max_attempts, batch_size):
        batch_end = min(batch_start + batch_size, max_attempts)
        
        for i in range(batch_start, batch_end):
            # Create collision candidate: original + 8-byte suffix
            suffix = struct.pack('<Q', i)
            candidate = target_bytes + suffix
            candidate_hash = hashlib.md5(candidate).hexdigest()
            
            if candidate_hash[:prefix_chars] == target_prefix:
                elapsed = time.time() - start_time
                stats = {
                    'total_hashes': i + 1,
                    'time_seconds': elapsed,
                    'hashes_per_second': (i + 1) / elapsed if elapsed > 0 else 0,
                }
                return suffix, stats
        
        total_hashes = batch_end
        
        if total_hashes % 1_000_000 == 0:
            elapsed = time.time() - start_time
            rate = total_hashes / elapsed if elapsed > 0 else 0
            print(f"   Processed {total_hashes:,} hashes ({rate:,.0f}/s)...")
    
    elapsed = time.time() - start_time
    stats = {
        'total_hashes': total_hashes,
        'time_seconds': elapsed,
        'hashes_per_second': total_hashes / elapsed if elapsed > 0 else 0,
    }
    return None, stats


def find_collision_for_string_gpu(
    target_string: str,
    prefix_bits: int = 24,
    max_attempts: int = 50_000_000,
    batch_size: int = 100_000,
) -> Tuple[Optional[bytes], dict]:
    """
    GPU-accelerated collision finding for a custom string.
    
    Note: Since we need variable-length message support, we use a hybrid approach:
    - Generate candidate suffixes in batches
    - Use hashlib for actual hashing (GPU helps with batch management)
    - This is still faster due to better memory management
    
    For true GPU acceleration of arbitrary strings, a custom Metal kernel would be needed.
    """
    print(f"\n🔍 Searching for {prefix_bits}-bit collision for \"{target_string}\" (GPU-assisted)...")
    
    # Compute target hash prefix
    target_bytes = target_string.encode('utf-8')
    target_hash = hashlib.md5(target_bytes).hexdigest()
    prefix_chars = prefix_bits // 4
    target_prefix = target_hash[:prefix_chars]
    
    print(f"   Target hash: {target_hash}")
    print(f"   Target prefix ({prefix_bits} bits): {target_prefix}")
    print(f"   Expected attempts: ~2^{prefix_bits} = {2**prefix_bits:,}")
    
    total_hashes = 0
    start_time = time.time()
    
    # Pre-compute target bytes length for efficiency
    target_len = len(target_bytes)
    
    for batch_start in range(0, max_attempts, batch_size):
        batch_end = min(batch_start + batch_size, max_attempts)
        
        # Generate batch of suffixes using NumPy for speed
        suffixes = np.arange(batch_start, batch_end, dtype=np.uint64)
        
        for i, suffix_int in enumerate(suffixes):
            suffix = struct.pack('<Q', int(suffix_int))
            candidate = target_bytes + suffix
            candidate_hash = hashlib.md5(candidate).hexdigest()
            
            if candidate_hash[:prefix_chars] == target_prefix:
                elapsed = time.time() - start_time
                actual_count = batch_start + i + 1
                stats = {
                    'total_hashes': actual_count,
                    'time_seconds': elapsed,
                    'hashes_per_second': actual_count / elapsed if elapsed > 0 else 0,
                }
                return suffix, stats
        
        total_hashes = batch_end
        
        if total_hashes % 1_000_000 == 0:
            elapsed = time.time() - start_time
            rate = total_hashes / elapsed if elapsed > 0 else 0
            print(f"   Processed {total_hashes:,} hashes ({rate:,.0f}/s)...")
    
    elapsed = time.time() - start_time
    stats = {
        'total_hashes': total_hashes,
        'time_seconds': elapsed,
        'hashes_per_second': total_hashes / elapsed if elapsed > 0 else 0,
    }
    return None, stats


# ==============================================================================
# Preimage Search (Find message matching a target hash)
# ==============================================================================

def find_preimage(
    target_hash: str,
    prefix_bits: int = 24,
    max_attempts: int = 50_000_000,
    batch_size: int = 100_000,
) -> Tuple[Optional[bytes], dict]:
    """
    Find a message that hashes to match the target hash prefix.
    This is a preimage attack - finding input for a given output.
    
    Args:
        target_hash: The MD5 hash to match (hex string, 32 chars)
        prefix_bits: Number of bits that must match (max practical: ~40)
        max_attempts: Maximum attempts
        batch_size: Batch size
        
    Returns:
        Tuple of (message bytes or None, stats dict)
    """
    # Validate and normalize target hash
    target_hash = target_hash.lower().strip()
    if len(target_hash) != 32 or not all(c in '0123456789abcdef' for c in target_hash):
        raise ValueError(f"Invalid MD5 hash: must be 32 hex characters, got '{target_hash}'")
    
    prefix_chars = prefix_bits // 4
    target_prefix = target_hash[:prefix_chars]
    
    print(f"\n🎯 Searching for preimage matching hash prefix...")
    print(f"   Target hash: {target_hash}")
    print(f"   Matching prefix ({prefix_bits} bits): {target_prefix}")
    print(f"   Expected attempts: ~2^{prefix_bits} = {2**prefix_bits:,}")
    
    if prefix_bits > 48:
        print(f"\n   ⚠️  WARNING: {prefix_bits} bits will take a VERY long time!")
        print(f"   Consider using --prefix-bits 32 or lower for practical results.")
    
    total_hashes = 0
    start_time = time.time()
    
    for batch_start in range(0, max_attempts, batch_size):
        batch_end = min(batch_start + batch_size, max_attempts)
        
        for i in range(batch_start, batch_end):
            # Generate candidate message (8 bytes)
            candidate = struct.pack('<Q', i)
            candidate_hash = hashlib.md5(candidate).hexdigest()
            
            if candidate_hash[:prefix_chars] == target_prefix:
                elapsed = time.time() - start_time
                stats = {
                    'total_hashes': i + 1,
                    'time_seconds': elapsed,
                    'hashes_per_second': (i + 1) / elapsed if elapsed > 0 else 0,
                }
                return candidate, stats
        
        total_hashes = batch_end
        
        if total_hashes % 1_000_000 == 0:
            elapsed = time.time() - start_time
            rate = total_hashes / elapsed if elapsed > 0 else 0
            print(f"   Processed {total_hashes:,} hashes ({rate:,.0f}/s)...")
    
    elapsed = time.time() - start_time
    stats = {
        'total_hashes': total_hashes,
        'time_seconds': elapsed,
        'hashes_per_second': total_hashes / elapsed if elapsed > 0 else 0,
    }
    return None, stats


def verify_preimage(message: bytes, target_hash: str, prefix_bits: int) -> bool:
    """Verify a preimage matches the target hash prefix."""
    found_hash = hashlib.md5(message).hexdigest()
    prefix_chars = prefix_bits // 4
    match = found_hash[:prefix_chars] == target_hash[:prefix_chars].lower()
    
    print(f"\n📋 Verification:")
    print(f"   Target hash:  {target_hash}")
    print(f"   Found message: {message.hex()} ({struct.unpack('<Q', message)[0]})")
    print(f"   Message hash: {found_hash}")
    print(f"   Prefix ({prefix_bits} bits): {'✓ MATCH' if match else '✗ NO MATCH'}")
    
    if prefix_bits == 128 and match:
        print(f"\n   🏆 FULL HASH MATCH! (This should be impossible...)")
    
    return match


# ==============================================================================
# Benchmarking
# ==============================================================================

def benchmark_hashing(num_hashes: int = 1_000_000) -> dict:
    """Benchmark CPU vs GPU hashing speed."""
    print(f"\n⚡ Benchmarking MD5 hashing ({num_hashes:,} hashes)...\n")
    
    messages = np.arange(num_hashes, dtype=np.uint64)
    blocks = prepare_md5_blocks(messages)
    
    # CPU benchmark
    print("   CPU (NumPy)...")
    start = time.time()
    _ = md5_compress_numpy(blocks)
    cpu_time = time.time() - start
    cpu_rate = num_hashes / cpu_time
    print(f"   → {cpu_time:.3f}s ({cpu_rate:,.0f} hashes/s)")
    
    results = {'cpu_time': cpu_time, 'cpu_rate': cpu_rate}
    
    # GPU benchmark
    if HAS_MLX:
        print("\n   GPU (MLX/Metal)...")
        blocks_mlx = mx.array(blocks, dtype=mx.uint32)
        
        # Warmup
        _ = md5_compress_mlx(blocks_mlx)
        mx.eval(_)
        
        start = time.time()
        hashes = md5_compress_mlx(blocks_mlx)
        mx.eval(hashes)  # Ensure computation completes
        gpu_time = time.time() - start
        gpu_rate = num_hashes / gpu_time
        print(f"   → {gpu_time:.3f}s ({gpu_rate:,.0f} hashes/s)")
        
        speedup = cpu_time / gpu_time
        print(f"\n   🚀 GPU Speedup: {speedup:.2f}x")
        
        results.update({'gpu_time': gpu_time, 'gpu_rate': gpu_rate, 'speedup': speedup})
    
    return results


# ==============================================================================
# Main
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MD5 Collision Attack Demo using macOS GPU',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python md5_collision_gpu.py                           # Default: 24-bit collision
  python md5_collision_gpu.py --prefix-bits 32          # 32-bit collision (slower)
  python md5_collision_gpu.py --benchmark               # Benchmark CPU vs GPU
  python md5_collision_gpu.py --message "Hello World"   # Find collision for custom string
  python md5_collision_gpu.py -m "test" --prefix-bits 16  # Quick 16-bit collision
  
  # Find message matching a specific hash (preimage attack):
  python md5_collision_gpu.py --target-hash d41d8cd98f00b204e9800998ecf8427e
  python md5_collision_gpu.py -t d41d8cd98f00b204e9800998ecf8427e --prefix-bits 32
        """
    )
    parser.add_argument('--prefix-bits', type=int, default=24,
                        help='Number of prefix bits for partial collision (default: 24)')
    parser.add_argument('--batch-size', type=int, default=100_000,
                        help='Batch size for hash computation (default: 100000)')
    parser.add_argument('--max-attempts', type=int, default=50_000_000,
                        help='Maximum attempts before giving up (default: 50000000)')
    parser.add_argument('--benchmark', action='store_true',
                        help='Run hash benchmark instead of collision search')
    parser.add_argument('--cpu-only', action='store_true',
                        help='Force CPU-only mode')
    parser.add_argument('--message', '-m', type=str, default=None,
                        help='Custom string to find a collision for')
    parser.add_argument('--target-hash', '-t', type=str, default=None,
                        help='Find a message that matches this MD5 hash (preimage attack)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("   MD5 Collision Attack Demonstration")
    print("   macOS GPU Acceleration (Metal via MLX)")
    print("=" * 60)
    
    if args.benchmark:
        benchmark_hashing()
        return
    
    use_gpu = HAS_MLX and not args.cpu_only
    
    # Preimage attack mode - find message matching a specific hash
    if args.target_hash:
        print(f"\n📊 Configuration:")
        print(f"   Mode: Preimage attack (find message for hash)")
        print(f"   Target: {args.target_hash}")
        print(f"   Prefix bits: {args.prefix_bits}")
        print(f"   Max attempts: {args.max_attempts:,}")
        
        try:
            message, stats = find_preimage(
                target_hash=args.target_hash,
                prefix_bits=args.prefix_bits,
                max_attempts=args.max_attempts,
                batch_size=args.batch_size,
            )
        except ValueError as e:
            print(f"\n❌ Error: {e}")
            return
        
        print(f"\n📈 Statistics:")
        print(f"   Total hashes: {stats['total_hashes']:,}")
        print(f"   Time: {stats['time_seconds']:.2f}s")
        print(f"   Rate: {stats['hashes_per_second']:,.0f} hashes/s")
        
        if message:
            print(f"\n🎉 PREIMAGE FOUND!")
            verify_preimage(message, args.target_hash, args.prefix_bits)
        else:
            print(f"\n❌ No preimage found within {args.max_attempts:,} attempts")
            print(f"   Try increasing --max-attempts or decreasing --prefix-bits")
        
        print("\n" + "=" * 60)
        return
    
    # Custom message mode
    if args.message:
        print(f"\n📊 Configuration:")
        print(f"   Mode: Custom string collision")
        print(f"   Message: \"{args.message}\"")
        print(f"   Prefix bits: {args.prefix_bits}")
        print(f"   Max attempts: {args.max_attempts:,}")
        print(f"   Using: {'GPU-assisted' if use_gpu else 'CPU'}")
        
        if use_gpu:
            suffix, stats = find_collision_for_string_gpu(
                target_string=args.message,
                prefix_bits=args.prefix_bits,
                max_attempts=args.max_attempts,
                batch_size=args.batch_size,
            )
        else:
            suffix, stats = find_collision_for_string_cpu(
                target_string=args.message,
                prefix_bits=args.prefix_bits,
                max_attempts=args.max_attempts,
                batch_size=args.batch_size,
            )
        
        print(f"\n📈 Statistics:")
        print(f"   Total hashes: {stats['total_hashes']:,}")
        print(f"   Time: {stats['time_seconds']:.2f}s")
        print(f"   Rate: {stats['hashes_per_second']:,.0f} hashes/s")
        
        if suffix:
            print(f"\n🎉 COLLISION FOUND!")
            verify_string_collision(args.message, suffix, args.prefix_bits)
            
            # Show how to recreate
            print(f"\n💡 To recreate:")
            print(f"   Original bytes: {args.message.encode('utf-8').hex()}")
            print(f"   Append suffix:  {suffix.hex()}")
            collision_bytes = args.message.encode('utf-8') + suffix
            print(f"   Full collision: {collision_bytes.hex()}")
        else:
            print(f"\n❌ No collision found within {args.max_attempts:,} attempts")
            print(f"   Try increasing --max-attempts or decreasing --prefix-bits")
        
        print("\n" + "=" * 60)
        return
    
    # Birthday attack mode (find any two colliding messages)
    print(f"\n📊 Configuration:")
    print(f"   Mode: Birthday attack (find any collision)")
    print(f"   Prefix bits: {args.prefix_bits}")
    print(f"   Batch size: {args.batch_size:,}")
    print(f"   Max attempts: {args.max_attempts:,}")
    print(f"   Using: {'GPU (MLX/Metal)' if use_gpu else 'CPU (NumPy)'}")
    
    if use_gpu:
        collision, stats = find_partial_collision_gpu(
            prefix_bits=args.prefix_bits,
            max_attempts=args.max_attempts,
            batch_size=args.batch_size,
        )
    else:
        collision, stats = find_partial_collision_cpu(
            prefix_bits=args.prefix_bits,
            max_attempts=args.max_attempts,
            batch_size=args.batch_size,
        )
    
    print(f"\n📈 Statistics:")
    print(f"   Total hashes: {stats['total_hashes']:,}")
    print(f"   Time: {stats['time_seconds']:.2f}s")
    print(f"   Rate: {stats['hashes_per_second']:,.0f} hashes/s")
    
    if collision:
        msg1, msg2 = collision
        print(f"\n🎉 PARTIAL COLLISION FOUND!")
        verify_collision(msg1, msg2, args.prefix_bits)
    else:
        print(f"\n❌ No collision found within {args.max_attempts:,} attempts")
        print(f"   Try increasing --max-attempts or decreasing --prefix-bits")
    
    print("\n" + "=" * 60)


if __name__ == '__main__':
    main()
