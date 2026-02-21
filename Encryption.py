"""
🔐 SEARCHABLE ENCRYPTION - INTERACTIVE DEMO
Hackathon Project - Takes input, shows output
"""

import hashlib
import hmac
import secrets
import base64
from typing import List, Dict, Set

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    CRYPTO_AVAILABLE = True
except ImportError:
    print("⚠️  Installing cryptography: pip install cryptography")
    CRYPTO_AVAILABLE = False


class DeterministicEncryption:
    """Deterministic Encryption - Same input = Same output"""
    
    def __init__(self):
        self.master_key = secrets.token_bytes(32)
    
    def encrypt(self, plaintext: str) -> Dict:
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'encryption', 100000, 32)
        # FIX: Use digestmod as keyword argument
        cipher_text = hmac.new(key, plaintext.encode(), digestmod=hashlib.sha256).digest()
        return {
            'ciphertext': base64.b64encode(cipher_text).decode(),
            'plaintext_length': len(plaintext)
        }
    
    def generate_trapdoor(self, keyword: str) -> str:
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'encryption', 100000, 32)
        # FIX: Use digestmod as keyword argument
        trapdoor = hmac.new(key, keyword.encode(), digestmod=hashlib.sha256).digest()
        return base64.b64encode(trapdoor).decode()
    
    def search(self, trapdoor: str, encrypted_data: List[Dict]) -> List[int]:
        matches = []
        for idx, data in enumerate(encrypted_data):
            if data['ciphertext'] == trapdoor:
                matches.append(idx)
        return matches


class SSEWithIndex:
    """SSE with Inverted Index - Efficient keyword search"""
    
    def __init__(self):
        self.master_key = secrets.token_bytes(32)
        self.index = {}
    
    def _generate_keyword_hash(self, keyword: str) -> str:
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'index', 100000, 32)
        # FIX: Use digestmod as keyword argument
        keyword_hash = hmac.new(key, keyword.lower().encode(), digestmod=hashlib.sha256).digest()
        return base64.b64encode(keyword_hash).decode()
    
    def _encrypt_content(self, plaintext: str) -> str:
        if not CRYPTO_AVAILABLE:
            return base64.b64encode(plaintext.encode()).decode()
        
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'content', 100000, 32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()
    
    def _decrypt_content(self, encrypted: str) -> str:
        if not CRYPTO_AVAILABLE:
            return base64.b64decode(encrypted).decode()
        
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'content', 100000, 32)
        data = base64.b64decode(encrypted)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext.decode()
    
    def build_index(self, documents: List[str]) -> List[Dict]:
        encrypted_docs = []
        for doc_id, document in enumerate(documents):
            encrypted_content = self._encrypt_content(document)
            keywords = set(document.lower().split())
            for keyword in keywords:
                keyword_hash = self._generate_keyword_hash(keyword)
                if keyword_hash not in self.index:
                    self.index[keyword_hash] = set()
                self.index[keyword_hash].add(doc_id)
            encrypted_docs.append({
                'doc_id': doc_id,
                'encrypted_content': encrypted_content
            })
        return encrypted_docs
    
    def generate_trapdoor(self, keyword: str) -> str:
        return self._generate_keyword_hash(keyword)
    
    def search(self, trapdoor: str, encrypted_docs: List[Dict]) -> List[Dict]:
        if trapdoor not in self.index:
            return []
        matching_ids = self.index[trapdoor]
        results = []
        for doc in encrypted_docs:
            if doc['doc_id'] in matching_ids:
                results.append({
                    'doc_id': doc['doc_id'],
                    'encrypted_content': doc['encrypted_content'],
                    'decrypted_content': self._decrypt_content(doc['encrypted_content'])
                })
        return results


def demonstrate_with_custom_input():
    """Interactive demo - judges can give you input"""
    
    print("\n" + "=" * 70)
    print("🔐 SEARCHABLE ENCRYPTION - CUSTOM INPUT DEMO")
    print("=" * 70)
    
    print("\n📝 This demo shows how to:")
    print("   1. Take custom input (documents)")
    print("   2. Encrypt the documents")
    print("   3. Search encrypted data")
    print("   4. Show results")
    
    # Get input from user (or use default for demo)
    print("\n" + "-" * 70)
    print("STEP 1: INPUT DOCUMENTS")
    print("-" * 70)
    
    use_default = input("\nUse example documents? (y/n) [default: y]: ").strip().lower()
    
    if use_default == 'n':
        print("\nEnter documents (one per line, empty line to finish):")
        documents = []
        while True:
            doc = input(f"Document {len(documents) + 1}: ").strip()
            if not doc:
                break
            documents.append(doc)
    else:
        documents = [
            "patient John has diabetes type 2",
            "patient Mary has hypertension",
            "patient John needs insulin medication",
            "patient Sarah has diabetes type 1"
        ]
        print("\n📄 Using example medical records:")
        for i, doc in enumerate(documents):
            print(f"   {i+1}. {doc}")
    
    if not documents:
        print("❌ No documents entered. Using default.")
        documents = ["test document one", "test document two"]
    
    # ENCRYPT THE DOCUMENTS
    print("\n" + "-" * 70)
    print("STEP 2: ENCRYPT DOCUMENTS")
    print("-" * 70)
    
    sse = SSEWithIndex()
    encrypted_docs = sse.build_index(documents)
    
    print(f"\n✅ Encrypted {len(documents)} documents")
    print(f"📇 Created searchable index with {len(sse.index)} unique keywords")
    print("\n🔒 Encrypted form (what server sees):")
    for doc in encrypted_docs[:3]:  # Show first 3
        print(f"   Doc {doc['doc_id']}: {doc['encrypted_content'][:60]}...")
    if len(encrypted_docs) > 3:
        print(f"   ... and {len(encrypted_docs) - 3} more documents")
    
    # SEARCH
    print("\n" + "-" * 70)
    print("STEP 3: SEARCH ENCRYPTED DATA")
    print("-" * 70)
    
    search_keyword = input("\nEnter search keyword [default: diabetes]: ").strip()
    if not search_keyword:
        search_keyword = "diabetes"
    
    print(f"\n🔍 Searching for: '{search_keyword}'")
    
    trapdoor = sse.generate_trapdoor(search_keyword)
    print(f"🎫 Generated search trapdoor: {trapdoor[:50]}...")
    
    results = sse.search(trapdoor, encrypted_docs)
    
    # SHOW RESULTS
    print("\n" + "-" * 70)
    print("STEP 4: RESULTS")
    print("-" * 70)
    
    if results:
        print(f"\n✅ Found {len(results)} matching document(s):\n")
        for result in results:
            print(f"📄 Document {result['doc_id'] + 1}:")
            print(f"   Original: {result['decrypted_content']}")
            print(f"   Encrypted: {result['encrypted_content'][:60]}...\n")
    else:
        print(f"\n❌ No documents found containing '{search_keyword}'")
    
    print("=" * 70)


def automated_demo():
    """Automated demo - no user input needed"""
    
    print("\n" + "=" * 70)
    print("🔐 AUTOMATED DEMO - NO INPUT REQUIRED")
    print("=" * 70)
    
    # EXAMPLE 1: Medical Records
    print("\n" + "=" * 70)
    print("EXAMPLE 1: MEDICAL RECORDS SEARCH")
    print("=" * 70)
    
    documents = [
        "Patient: John Doe, Condition: diabetes type 2, Medication: metformin",
        "Patient: Jane Smith, Condition: hypertension, Medication: lisinopril",
        "Patient: Bob Johnson, Condition: diabetes type 1, Medication: insulin",
        "Patient: Alice Brown, Condition: asthma, Medication: albuterol"
    ]
    
    print("\n📄 INPUT (Original medical records):")
    for i, doc in enumerate(documents, 1):
        print(f"   {i}. {doc}")
    
    sse = SSEWithIndex()
    encrypted_docs = sse.build_index(documents)
    
    print("\n🔒 ENCRYPTED (What's stored on server):")
    for doc in encrypted_docs:
        print(f"   Record {doc['doc_id'] + 1}: {doc['encrypted_content'][:60]}...")
    
    search_term = "diabetes"
    print(f"\n🔍 SEARCH: Doctor searches for '{search_term}'")
    
    trapdoor = sse.generate_trapdoor(search_term)
    results = sse.search(trapdoor, encrypted_docs)
    
    print(f"\n✅ OUTPUT (Search results):")
    print(f"   Found {len(results)} patient(s) with {search_term}:\n")
    for result in results:
        print(f"   📋 Record {result['doc_id'] + 1}: {result['decrypted_content']}")
    
    # EXAMPLE 2: Pattern Analysis
    print("\n" + "=" * 70)
    print("EXAMPLE 2: SECURITY ANALYSIS - PATTERN LEAKAGE")
    print("=" * 70)
    
    de = DeterministicEncryption()
    words = ["apple", "banana", "apple", "cherry", "banana", "apple"]
    
    print("\n📄 INPUT (Word sequence):")
    print(f"   {words}")
    
    encrypted = [de.encrypt(word) for word in words]
    ciphertexts = [e['ciphertext'] for e in encrypted]
    
    print("\n🔒 ENCRYPTED:")
    for i, ct in enumerate(ciphertexts):
        print(f"   {i+1}. {ct[:40]}...")
    
    print("\n🔍 PATTERN ANALYSIS:")
    print(f"   'apple' appears at positions: {[i+1 for i, w in enumerate(words) if w == 'apple']}")
    print(f"   All have same ciphertext: {ciphertexts[0][:40]}...")
    
    print("\n✅ OUTPUT (Security insight):")
    print("   ⚠️  Same words → Same ciphertext (reveals patterns)")
    print("   💡 Trade-off: Fast search vs Pattern leakage")
    
    print("\n" + "=" * 70)


def main():
    """Main function - choose demo mode"""
    
    print("\n" + "=" * 70)
    print("🔐 SECURED STRING MATCHING USING SEARCHABLE ENCRYPTION")
    print("   Hackathon Project Demo")
    print("=" * 70)
    
    print("\n📊 Choose demo mode:")
    print("   1. Interactive (judges give you input)")
    print("   2. Automated (pre-defined examples)")
    print("   3. Both")
    
    choice = input("\nChoice [default: 2]: ").strip()
    
    if choice == '1':
        demonstrate_with_custom_input()
    elif choice == '3':
        automated_demo()
        print("\n\n")
        demonstrate_with_custom_input()
    else:
        # Default: automated demo
        automated_demo()
    
    print("\n" + "=" * 70)
    print("✨ DEMO COMPLETED!")
    print("=" * 70)
    print("\n💡 Key Takeaways:")
    print("   • Can search encrypted data without decryption")
    print("   • Multiple methods with different trade-offs")
    print("   • Real-world applications: healthcare, email, cloud storage")
    print("   • Balance between security and functionality")
    print("\n🎯 Thank you! Questions?")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
