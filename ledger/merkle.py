import hashlib
from typing import List, Dict, Any, Optional

def hash_pair(left: str, right: str) -> str:
    """Computes SHA-256 of concatenated left and right hex hashes."""
    combined = left + right
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()

class MerkleTree:
    """Computes Merkle root and inclusion proofs for a list of entry hashes."""

    def __init__(self, leaf_hashes: List[str]):
        if not leaf_hashes:
            raise ValueError("Leaf hashes cannot be empty")
        self.leaf_hashes = leaf_hashes
        self.levels: List[List[str]] = [leaf_hashes]
        self._build_tree()

    def _build_tree(self):
        current_level = self.leaf_hashes
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = left  # duplicate odd leaf
                next_level.append(hash_pair(left, right))
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> List[Dict[str, str]]:
        """Returns sibling hashes and direction for audit proof."""
        proof = []
        idx = leaf_index
        for level in self.levels[:-1]:
            is_right = (idx % 2 == 1)
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(level):
                sibling = level[sibling_idx]
            else:
                sibling = level[idx]
            proof.append({
                "sibling": sibling,
                "position": "left" if is_right else "right"
            })
            idx = idx // 2
        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        current = leaf_hash
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "left":
                current = hash_pair(sibling, current)
            else:
                current = hash_pair(current, sibling)
        return current == expected_root
