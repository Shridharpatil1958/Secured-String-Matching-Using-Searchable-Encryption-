"""
🔐 SEARCHABLE ENCRYPTION - STREAMLIT APP  (MySQL edition)
Hackathon Project
Run with: streamlit run streamlit_app.py
Dependencies: pip install streamlit cryptography mysql-connector-python
"""

import hashlib
import hmac
import secrets
import base64
from typing import List, Dict
from collections import Counter

import streamlit as st

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="🔐 Searchable Encryption Demo",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
code, pre { font-family: 'JetBrains Mono', monospace !important; }

.hero {
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 50%, #16213e 100%);
    border-radius: 16px;
    padding: 2.5rem 2rem;
    margin-bottom: 1.5rem;
    border: 1px solid #2a2a4a;
    text-align: center;
}
.hero h1 { font-family:'Syne',sans-serif; font-weight:800; font-size:2.4rem; color:#e0e0ff; margin:0 0 0.3rem 0; }
.hero p  { color:#7878aa; font-size:1rem; margin:0; }

.step-card {
    background:#0f0f1a; border:1px solid #2a2a4a;
    border-left:4px solid #6c63ff; border-radius:10px;
    padding:1rem 1.2rem; margin-bottom:0.8rem;
}
.step-card h4 { color:#c0b8ff; margin:0 0 0.3rem 0; font-size:0.9rem; text-transform:uppercase; letter-spacing:1px; }
.step-card p  { color:#888; margin:0; font-size:0.85rem; }

.enc-block {
    background:#060610; border:1px solid #1e1e3a; border-radius:8px;
    padding:0.7rem 1rem; font-family:'JetBrains Mono',monospace;
    font-size:0.75rem; color:#50fa7b; word-break:break-all; margin-bottom:0.4rem;
}

.result-card {
    background:linear-gradient(135deg,#0d1f12,#0f0f1a);
    border:1px solid #1e3a2a; border-left:4px solid #50fa7b;
    border-radius:10px; padding:1rem 1.2rem; margin-bottom:0.6rem;
}
.result-card .doc-id   { color:#50fa7b; font-weight:700; font-size:0.8rem; text-transform:uppercase; letter-spacing:1px; }
.result-card .original { color:#e0e0ff; font-size:0.95rem; margin:0.3rem 0; }
.result-card .cipher   { color:#555; font-family:'JetBrains Mono',monospace; font-size:0.7rem; word-break:break-all; }

.no-result {
    background:#1a0a0a; border:1px solid #3a1a1a; border-left:4px solid #ff5555;
    border-radius:10px; padding:1rem 1.2rem; color:#ff6b6b;
}

.pattern-card {
    background:#0f0f1a; border:1px solid #2a2a4a; border-radius:10px;
    padding:1rem 1.2rem; margin-bottom:0.5rem;
}
.pattern-card .word-label { font-weight:700; }
.pattern-card .ct { color:#ffb86c; font-family:'JetBrains Mono',monospace; font-size:0.72rem; word-break:break-all; }

.metric-box {
    background:#0f0f1a; border:1px solid #2a2a4a; border-radius:10px;
    padding:1rem; text-align:center; margin-bottom:0.5rem;
}
.metric-box .num   { font-size:2rem; font-weight:800; color:#6c63ff; }
.metric-box .label { font-size:0.8rem; color:#666; text-transform:uppercase; letter-spacing:1px; }

.trapdoor {
    background:#0a0a1a; border:1px dashed #6c63ff; border-radius:8px;
    padding:0.7rem 1rem; font-family:'JetBrains Mono',monospace;
    font-size:0.75rem; color:#bd93f9; word-break:break-all; margin:0.5rem 0 1rem 0;
}

.db-badge {
    background:#0a1a0a; border:1px solid #1e3a1e; border-radius:6px;
    padding:0.3rem 0.7rem; font-size:0.75rem; color:#50fa7b; display:inline-block;
    font-family:'JetBrains Mono',monospace; margin-top:0.3rem;
}
.db-badge-warn {
    background:#1a0a0a; border:1px solid #3a1a1a; border-radius:6px;
    padding:0.3rem 0.7rem; font-size:0.75rem; color:#ff6b6b; display:inline-block;
    font-family:'JetBrains Mono',monospace; margin-top:0.3rem;
}

.explorer-header {
    background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 100%);
    border: 1px solid #2a2a4a;
    border-left: 4px solid #ffb86c;
    border-radius: 10px;
    padding: 1rem 1.2rem;
    margin-bottom: 1rem;
}
.explorer-header h4 { color:#ffb86c; margin:0 0 0.3rem 0; font-size:0.9rem; text-transform:uppercase; letter-spacing:1px; }
.explorer-header p  { color:#888; margin:0; font-size:0.85rem; }

.stat-card {
    background:#0f0f1a; border:1px solid #2a2a4a; border-radius:10px;
    padding:1.2rem; text-align:center; margin-bottom:0.5rem;
}
.stat-card .stat-num   { font-size:2.2rem; font-weight:800; color:#ffb86c; }
.stat-card .stat-label { font-size:0.78rem; color:#666; text-transform:uppercase; letter-spacing:1px; margin-top:0.2rem; }

.table-info {
    background:#060610; border:1px solid #1e1e3a; border-radius:8px;
    padding:0.6rem 1rem; font-family:'JetBrains Mono',monospace;
    font-size:0.78rem; color:#bd93f9; margin-bottom:0.8rem;
}

section[data-testid="stSidebar"] { background:#0a0a14; border-right:1px solid #1e1e3a; }
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# DB bootstrap
# ══════════════════════════════════════════════════════════════════════════════

try:
    import db
    _db_ok, _db_msg = db.init_db()
    DB_AVAILABLE = _db_ok
except ImportError:
    DB_AVAILABLE = False
    _db_msg = "db.py not found – place db.py next to this file and run: pip install mysql-connector-python"
except Exception as exc:
    DB_AVAILABLE = False
    _db_msg = str(exc)


# ══════════════════════════════════════════════════════════════════════════════
# Crypto libraries
# ══════════════════════════════════════════════════════════════════════════════

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# Crypto Classes
# ══════════════════════════════════════════════════════════════════════════════

class DeterministicEncryption:
    """Deterministic Encryption – same input always produces same ciphertext."""

    def __init__(self):
        self.master_key = secrets.token_bytes(32)

    def encrypt(self, plaintext: str) -> Dict:
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'encryption', 100000, 32)
        cipher_text = hmac.new(key, plaintext.encode(), digestmod=hashlib.sha256).digest()
        return {
            'ciphertext': base64.b64encode(cipher_text).decode(),
            'plaintext_length': len(plaintext),
        }

    def generate_trapdoor(self, keyword: str) -> str:
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'encryption', 100000, 32)
        trapdoor = hmac.new(key, keyword.encode(), digestmod=hashlib.sha256).digest()
        return base64.b64encode(trapdoor).decode()

    def search(self, trapdoor: str, encrypted_data: List[Dict]) -> List[int]:
        return [i for i, d in enumerate(encrypted_data) if d['ciphertext'] == trapdoor]


class SSEWithIndex:
    """SSE with Inverted Index – efficient keyword search over encrypted docs."""

    def __init__(self):
        self.master_key = secrets.token_bytes(32)
        self.index: Dict[str, set] = {}

    def _generate_keyword_hash(self, keyword: str) -> str:
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'index', 100000, 32)
        kh = hmac.new(key, keyword.lower().encode(), digestmod=hashlib.sha256).digest()
        return base64.b64encode(kh).decode()

    def _encrypt_content(self, plaintext: str) -> str:
        if not CRYPTO_AVAILABLE:
            return base64.b64encode(plaintext.encode()).decode()
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'content', 100000, 32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        return base64.b64encode(iv + ct).decode()

    def _decrypt_content(self, encrypted: str) -> str:
        if not CRYPTO_AVAILABLE:
            return base64.b64decode(encrypted).decode()
        key = hashlib.pbkdf2_hmac('sha256', self.master_key, b'content', 100000, 32)
        data = base64.b64decode(encrypted)
        iv, ct = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_pt = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_pt) + unpadder.finalize()).decode()

    def build_index(self, documents: List[str]) -> List[Dict]:
        self.index = {}
        encrypted_docs = []
        for doc_id, document in enumerate(documents):
            enc = self._encrypt_content(document)
            for kw in set(document.lower().split()):
                kh = self._generate_keyword_hash(kw)
                self.index.setdefault(kh, set()).add(doc_id)
            encrypted_docs.append({'doc_id': doc_id, 'encrypted_content': enc})
        return encrypted_docs

    def generate_trapdoor(self, keyword: str) -> str:
        return self._generate_keyword_hash(keyword)

    def search(self, trapdoor: str, encrypted_docs: List[Dict]) -> List[Dict]:
        if trapdoor not in self.index:
            return []
        ids = self.index[trapdoor]
        return [
            {**doc, 'decrypted_content': self._decrypt_content(doc['encrypted_content'])}
            for doc in encrypted_docs if doc['doc_id'] in ids
        ]


# ══════════════════════════════════════════════════════════════════════════════
# Session State initialisation
# ══════════════════════════════════════════════════════════════════════════════

_defaults = {
    'sse': None,
    'de': None,
    'encrypted_docs': [],
    'documents': [],
    'search_results': None,
    'trapdoor': None,
    'pattern_words': [],
    'pattern_enc': [],
    'session_id': None,
    'de_session_id': None,
    'explorer_sid': None,
}
for _k, _v in _defaults.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v


# ══════════════════════════════════════════════════════════════════════════════
# Sidebar
# ══════════════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("## 🔐 Navigation")
    mode = st.radio(
        "Demo Mode",
        [
            "🏥 SSE – Medical Records",
            "🔢 Pattern Analysis",
            "✏️ Custom Documents",
            "🗄️ Data Explorer",
        ],
        label_visibility="collapsed",
    )
    st.markdown("---")

    # MySQL status
    st.markdown("### 🗄️ MySQL Status")
    if DB_AVAILABLE:
        st.success("Connected")
        _stats = db.get_global_stats()
        if _stats:
            _c1, _c2 = st.columns(2)
            _c1.metric("Sessions",    _stats.get("total_sessions", 0))
            _c2.metric("Docs",        _stats.get("total_docs", 0))
            _c3, _c4 = st.columns(2)
            _c3.metric("Index rows",  _stats.get("total_index_entries", 0))
            _c4.metric("Searches",    _stats.get("total_searches", 0))
    else:
        st.error(f"Not connected\n\n{_db_msg}")

    st.markdown("---")
    st.markdown("### ℹ️ How it works")
    st.markdown(
        "1. Documents are **AES-CBC encrypted**\n"
        "2. Keywords are hashed with **HMAC-SHA256**\n"
        "3. An **inverted index** maps keyword-hashes → doc IDs\n"
        "4. Search sends a **trapdoor** (keyword hash) — server never sees plaintext\n"
        "5. All data is **persisted to MySQL**"
    )
    st.markdown("---")
    if not CRYPTO_AVAILABLE:
        st.warning("⚠️ `cryptography` not installed.\n`pip install cryptography`\nUsing base64 fallback.")
    else:
        st.success("✅ AES-CBC encryption active")


# ══════════════════════════════════════════════════════════════════════════════
# Hero banner
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<div class="hero">
    <h1>🔐 Searchable Encryption</h1>
    <p>Search encrypted data — without ever decrypting it first</p>
</div>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# MODE 1 — SSE Medical Records
# ══════════════════════════════════════════════════════════════════════════════

if mode == "🏥 SSE – Medical Records":

    st.markdown("### Step-by-step walkthrough")
    col1, col2 = st.columns(2, gap="large")

    # ── Left: Encrypt ─────────────────────────────────────────────────────────
    with col1:
        st.markdown("""
        <div class="step-card">
            <h4>① Encrypt &amp; Index Documents</h4>
            <p>Documents are AES-encrypted; keywords are hashed into a searchable index.
               Everything is saved to MySQL.</p>
        </div>""", unsafe_allow_html=True)

        default_docs = (
            "Patient: John Doe, Condition: diabetes type 2, Medication: metformin\n"
            "Patient: Jane Smith, Condition: hypertension, Medication: lisinopril\n"
            "Patient: Bob Johnson, Condition: diabetes type 1, Medication: insulin\n"
            "Patient: Alice Brown, Condition: asthma, Medication: albuterol"
        )
        raw = st.text_area("Documents (one per line)", value=default_docs, height=160)

        if st.button("🔒 Encrypt & Build Index", use_container_width=True, type="primary"):
            docs = [d.strip() for d in raw.strip().splitlines() if d.strip()]
            if not docs:
                st.error("Please enter at least one document.")
            else:
                sse = SSEWithIndex()
                enc_docs = sse.build_index(docs)

                sid = None
                if DB_AVAILABLE:
                    sid = db.upsert_session(sse.master_key, "sse_medical")
                    if sid:
                        db.save_encrypted_docs(sid, enc_docs)
                        db.save_keyword_index(sid, sse.index)

                st.session_state.update(
                    sse=sse, encrypted_docs=enc_docs,
                    documents=docs, search_results=None,
                    trapdoor=None, session_id=sid,
                )

                msg = f"✅ Encrypted {len(docs)} documents · {len(sse.index)} keyword hashes indexed"
                if DB_AVAILABLE and sid:
                    msg += f"  |  💾 saved to MySQL (session {sid})"
                st.success(msg)

        if st.session_state.encrypted_docs:
            st.markdown("---")
            m1, m2 = st.columns(2)
            m1.markdown(f'<div class="metric-box"><div class="num">{len(st.session_state.documents)}</div><div class="label">Documents</div></div>', unsafe_allow_html=True)
            m2.markdown(f'<div class="metric-box"><div class="num">{len(st.session_state.sse.index)}</div><div class="label">Index Entries</div></div>', unsafe_allow_html=True)

            if st.session_state.session_id:
                st.markdown(f'<span class="db-badge">🗄️ MySQL session ID: {st.session_state.session_id}</span>', unsafe_allow_html=True)

            st.markdown("**🔒 Encrypted form (server view):**")
            for doc in st.session_state.encrypted_docs:
                st.markdown(
                    f'<div class="enc-block">Doc {doc["doc_id"]+1}: {doc["encrypted_content"][:72]}…</div>',
                    unsafe_allow_html=True,
                )

    # ── Right: Search ─────────────────────────────────────────────────────────
    with col2:
        st.markdown("""
        <div class="step-card">
            <h4>② Search Without Decrypting</h4>
            <p>A trapdoor is generated from your keyword and matched against the index.
               Each search is logged to MySQL (trapdoor only — no plaintext stored).</p>
        </div>""", unsafe_allow_html=True)

        keyword = st.text_input("Search keyword", value="diabetes", placeholder="e.g. diabetes, insulin …")

        if st.button("🔍 Search Encrypted Index", use_container_width=True):
            if not st.session_state.sse:
                st.warning("⚠️ Encrypt documents first (left panel).")
            elif not keyword.strip():
                st.warning("Enter a keyword.")
            else:
                td = st.session_state.sse.generate_trapdoor(keyword.strip())
                results = st.session_state.sse.search(td, st.session_state.encrypted_docs)

                if DB_AVAILABLE and st.session_state.session_id:
                    db.log_search(st.session_state.session_id, td, len(results))

                st.session_state.trapdoor = td
                st.session_state.search_results = results

        if st.session_state.trapdoor:
            st.markdown("**🎫 Search trapdoor sent to server:**")
            st.markdown(f'<div class="trapdoor">{st.session_state.trapdoor}</div>', unsafe_allow_html=True)

        if st.session_state.search_results is not None:
            results = st.session_state.search_results
            if results:
                st.markdown(f"**✅ {len(results)} matching document(s) found:**")
                for r in results:
                    st.markdown(f"""
                    <div class="result-card">
                        <div class="doc-id">Document {r['doc_id']+1}</div>
                        <div class="original">{r['decrypted_content']}</div>
                        <div class="cipher">{r['encrypted_content'][:80]}…</div>
                    </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="no-result">❌ No documents found containing <strong>\'{keyword}\'</strong></div>', unsafe_allow_html=True)

        if DB_AVAILABLE and st.session_state.session_id:
            history = db.get_search_history(st.session_state.session_id)
            if history:
                with st.expander(f"📜 Search log ({len(history)} queries stored in MySQL)"):
                    for h in history:
                        st.markdown(
                            f"`{str(h['trapdoor'])[:32]}…` → **{h['results_count']}** result(s) at `{h['searched_at']}`"
                        )


# ══════════════════════════════════════════════════════════════════════════════
# MODE 2 — Pattern Analysis
# ══════════════════════════════════════════════════════════════════════════════

elif mode == "🔢 Pattern Analysis":

    st.markdown("### Deterministic encryption reveals frequency patterns")
    st.info("⚠️ **Security insight:** Deterministic encryption enables fast search, but repeated words always produce the same ciphertext — leaking frequency information to an attacker.")

    col1, col2 = st.columns(2, gap="large")

    with col1:
        raw_words = st.text_input(
            "Word sequence (comma-separated)",
            value="apple, banana, apple, cherry, banana, apple",
        )
        if st.button("🔒 Encrypt Words", use_container_width=True, type="primary"):
            words = [w.strip() for w in raw_words.split(",") if w.strip()]
            if not words:
                st.error("Enter at least one word.")
            else:
                de = DeterministicEncryption()
                enc = [de.encrypt(w) for w in words]

                de_sid = None
                if DB_AVAILABLE:
                    de_sid = db.upsert_session(de.master_key, "deterministic_pattern")
                    if de_sid:
                        db.save_pattern_words(de_sid, words, enc)

                st.session_state.de = de
                st.session_state.pattern_words = words
                st.session_state.pattern_enc = enc
                st.session_state.de_session_id = de_sid

                msg = f"✅ Encrypted {len(words)} words"
                if DB_AVAILABLE and de_sid:
                    msg += f"  |  💾 saved to MySQL (session {de_sid})"
                st.success(msg)

    with col2:
        if st.session_state.pattern_words:
            words = st.session_state.pattern_words
            enc   = st.session_state.pattern_enc
            palette = ["#6c63ff", "#50fa7b", "#ffb86c", "#ff79c6", "#8be9fd"]
            seen: Dict[str, str] = {}

            if st.session_state.de_session_id:
                st.markdown(f'<span class="db-badge">🗄️ MySQL session ID: {st.session_state.de_session_id}</span>', unsafe_allow_html=True)

            st.markdown("**🔒 Ciphertexts:**")
            for w, e in zip(words, enc):
                ct = e['ciphertext']
                color = seen.setdefault(ct, palette[len(seen) % len(palette)])
                st.markdown(
                    f'<div class="pattern-card">'
                    f'<span class="word-label" style="color:{color}">{w}</span><br>'
                    f'<span class="ct">{ct[:64]}…</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            st.markdown("**📊 Frequency analysis (attacker's view):**")
            freq = Counter(zip(words, [e['ciphertext'] for e in enc]))
            for (w, _), count in freq.most_common():
                st.markdown(f"- **{w}** → appears **{count}×** — identical ciphertext each time")


# ══════════════════════════════════════════════════════════════════════════════
# MODE 3 — Custom Documents
# ══════════════════════════════════════════════════════════════════════════════

elif mode == "✏️ Custom Documents":

    st.markdown("### Try it with your own data")

    with st.form("custom_form"):
        raw = st.text_area(
            "Enter your documents (one per line)",
            placeholder=(
                "Alice joined the project in March\n"
                "Bob handles the database layer\n"
                "Alice reviewed the pull request"
            ),
            height=200,
        )
        keyword = st.text_input("Keyword to search for", placeholder="e.g. Alice")
        submitted = st.form_submit_button("🔐 Encrypt & Search", use_container_width=True, type="primary")

    if submitted:
        docs = [d.strip() for d in raw.strip().splitlines() if d.strip()]
        if not docs:
            st.error("Please enter at least one document.")
        elif not keyword.strip():
            st.error("Please enter a search keyword.")
        else:
            with st.spinner("Encrypting and searching…"):
                sse = SSEWithIndex()
                enc_docs = sse.build_index(docs)
                td = sse.generate_trapdoor(keyword.strip())
                results = sse.search(td, enc_docs)

                custom_sid = None
                if DB_AVAILABLE:
                    custom_sid = db.upsert_session(sse.master_key, "custom")
                    if custom_sid:
                        db.save_encrypted_docs(custom_sid, enc_docs)
                        db.save_keyword_index(custom_sid, sse.index)
                        db.log_search(custom_sid, td, len(results))

            c1, c2, c3 = st.columns(3)
            c1.markdown(f'<div class="metric-box"><div class="num">{len(docs)}</div><div class="label">Documents</div></div>', unsafe_allow_html=True)
            c2.markdown(f'<div class="metric-box"><div class="num">{len(sse.index)}</div><div class="label">Index entries</div></div>', unsafe_allow_html=True)
            c3.markdown(f'<div class="metric-box"><div class="num">{len(results)}</div><div class="label">Matches</div></div>', unsafe_allow_html=True)

            if DB_AVAILABLE and custom_sid:
                st.markdown(f'<span class="db-badge">🗄️ Saved to MySQL · session ID: {custom_sid}</span>', unsafe_allow_html=True)
            elif DB_AVAILABLE:
                st.markdown('<span class="db-badge-warn">⚠️ MySQL save failed — check connection</span>', unsafe_allow_html=True)

            st.markdown("---")
            left, right = st.columns(2)

            with left:
                st.markdown("**🔒 Encrypted documents (server view):**")
                for doc in enc_docs:
                    st.markdown(
                        f'<div class="enc-block">Doc {doc["doc_id"]+1}: {doc["encrypted_content"][:72]}…</div>',
                        unsafe_allow_html=True,
                    )

            with right:
                st.markdown(f"**🔍 Search results for `{keyword.strip()}`:**")
                st.markdown(f'<div class="trapdoor">{td}</div>', unsafe_allow_html=True)
                if results:
                    for r in results:
                        st.markdown(f"""
                        <div class="result-card">
                            <div class="doc-id">Document {r['doc_id']+1}</div>
                            <div class="original">{r['decrypted_content']}</div>
                            <div class="cipher">{r['encrypted_content'][:80]}…</div>
                        </div>""", unsafe_allow_html=True)
                else:
                    st.markdown(f'<div class="no-result">❌ No documents found containing <strong>\'{keyword.strip()}\'</strong></div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# MODE 4 — Data Explorer
# ══════════════════════════════════════════════════════════════════════════════

elif mode == "🗄️ Data Explorer":

    st.markdown("### 🗄️ MySQL Data Explorer")
    st.markdown("Browse all data stored in the database across every session.")

    if not DB_AVAILABLE:
        st.error(f"❌ MySQL is not connected.\n\n{_db_msg}")
        st.stop()

    # ── Global stats ──────────────────────────────────────────────────────────
    stats = db.get_global_stats()
    g1, g2, g3, g4 = st.columns(4)
    g1.markdown(f'<div class="stat-card"><div class="stat-num">{stats.get("total_sessions", 0)}</div><div class="stat-label">Total Sessions</div></div>', unsafe_allow_html=True)
    g2.markdown(f'<div class="stat-card"><div class="stat-num">{stats.get("total_docs", 0)}</div><div class="stat-label">Encrypted Docs</div></div>', unsafe_allow_html=True)
    g3.markdown(f'<div class="stat-card"><div class="stat-num">{stats.get("total_index_entries", 0)}</div><div class="stat-label">Index Entries</div></div>', unsafe_allow_html=True)
    g4.markdown(f'<div class="stat-card"><div class="stat-num">{stats.get("total_searches", 0)}</div><div class="stat-label">Total Searches</div></div>', unsafe_allow_html=True)

    st.markdown("---")

    # Refresh button
    if st.button("🔄 Refresh Data", use_container_width=False):
        st.rerun()

    # ── 5 tabs ────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Sessions",
        "🔒 Encrypted Documents",
        "🔑 Keyword Index",
        "🔍 Search Log",
        "🔢 Pattern Words",
    ])

    # ── Tab 1 : Sessions ──────────────────────────────────────────────────────
    with tab1:
        st.markdown("""
        <div class="explorer-header">
            <h4>sessions table</h4>
            <p>One row per encryption session. <code>session_key</code> is SHA-256 of the master key — the actual key is never stored.</p>
        </div>""", unsafe_allow_html=True)

        sessions = db.get_all_sessions()

        if not sessions:
            st.info("No sessions yet. Go to **🏥 SSE – Medical Records** and click **Encrypt & Build Index** to create one.")
        else:
            display_sessions = [
                {
                    "ID":                        s["id"],
                    "Mode":                      s["mode"],
                    "Session Key (truncated)":   str(s["session_key"])[:24] + "…",
                    "Created At":                s["created_at"],
                }
                for s in sessions
            ]
            st.dataframe(display_sessions, use_container_width=True, hide_index=True)
            st.markdown(f'<div class="table-info">📊 {len(sessions)} session(s) found</div>', unsafe_allow_html=True)

            st.session_state["explorer_sid"] = st.selectbox(
                "Select a session to inspect in the other tabs:",
                options=[s["id"] for s in sessions],
                format_func=lambda sid: f"Session {sid}  —  {next(s['mode'] for s in sessions if s['id'] == sid)}",
            )

    # ── Tab 2 : Encrypted Documents ───────────────────────────────────────────
    with tab2:
        st.markdown("""
        <div class="explorer-header">
            <h4>encrypted_documents table</h4>
            <p>AES-CBC ciphertexts stored per document. The server only ever sees these blobs — never the plaintext.</p>
        </div>""", unsafe_allow_html=True)

        sessions_list = db.get_all_sessions()
        if not sessions_list:
            st.info("No sessions yet.")
        else:
            sid_docs = st.selectbox(
                "Session",
                options=[s["id"] for s in sessions_list],
                format_func=lambda x: f"Session {x}  —  {next(s['mode'] for s in sessions_list if s['id'] == x)}",
                key="docs_sid",
            )
            enc_docs = db.load_encrypted_docs(sid_docs)

            if not enc_docs:
                st.info(f"No documents found for session {sid_docs}.")
            else:
                display_docs = [
                    {
                        "Doc #":                    d["doc_id"] + 1,
                        "Ciphertext (first 60)":    str(d["encrypted_content"])[:60] + "…",
                        "Total Length (chars)":     len(str(d["encrypted_content"])),
                    }
                    for d in enc_docs
                ]
                st.dataframe(display_docs, use_container_width=True, hide_index=True)
                st.markdown(f'<div class="table-info">📊 {len(enc_docs)} document(s) for session {sid_docs}</div>', unsafe_allow_html=True)

                with st.expander("🔍 View full ciphertexts"):
                    for d in enc_docs:
                        st.markdown(f"**Doc {d['doc_id'] + 1}:**")
                        st.markdown(f'<div class="enc-block">{d["encrypted_content"]}</div>', unsafe_allow_html=True)

    # ── Tab 3 : Keyword Index ─────────────────────────────────────────────────
    with tab3:
        st.markdown("""
        <div class="explorer-header">
            <h4>keyword_index table</h4>
            <p>Maps HMAC-SHA256 keyword hashes → document IDs. No plaintext keyword is ever stored — only the hash.</p>
        </div>""", unsafe_allow_html=True)

        sessions_list = db.get_all_sessions()
        if not sessions_list:
            st.info("No sessions yet.")
        else:
            sid_idx = st.selectbox(
                "Session",
                options=[s["id"] for s in sessions_list],
                format_func=lambda x: f"Session {x}  —  {next(s['mode'] for s in sessions_list if s['id'] == x)}",
                key="idx_sid",
            )
            index = db.load_keyword_index(sid_idx)

            if not index:
                st.info(f"No index entries for session {sid_idx}.")
            else:
                rows = [
                    {
                        "Entry #":                  i + 1,
                        "Keyword Hash (truncated)": kh[:32] + "…",
                        "Matching Doc IDs":         ", ".join(str(d + 1) for d in sorted(doc_ids)),
                        "Doc Count":                len(doc_ids),
                    }
                    for i, (kh, doc_ids) in enumerate(index.items())
                ]
                st.dataframe(rows, use_container_width=True, hide_index=True)
                st.markdown(f'<div class="table-info">📊 {len(index)} unique keyword hash(es) for session {sid_idx}</div>', unsafe_allow_html=True)
                st.info(
                    "💡 **Security note:** An attacker with access to this table sees only hashes and doc IDs — "
                    "they cannot reverse the hash to recover the original keyword."
                )

    # ── Tab 4 : Search Log ────────────────────────────────────────────────────
    with tab4:
        st.markdown("""
        <div class="explorer-header">
            <h4>search_log table</h4>
            <p>Every search is recorded as a trapdoor hash + result count. The plaintext keyword is never stored.</p>
        </div>""", unsafe_allow_html=True)

        sessions_list = db.get_all_sessions()
        if not sessions_list:
            st.info("No sessions yet.")
        else:
            filter_col, _ = st.columns([2, 3])
            with filter_col:
                sid_log = st.selectbox(
                    "Filter by session",
                    options=["All sessions"] + [s["id"] for s in sessions_list],
                    format_func=lambda x: "All sessions" if x == "All sessions"
                        else f"Session {x}  —  {next(s['mode'] for s in sessions_list if s['id'] == x)}",
                    key="log_sid",
                )

            if sid_log == "All sessions":
                all_history = []
                for s in sessions_list:
                    for entry in db.get_search_history(s["id"]):
                        entry["session_id"] = s["id"]
                        entry["mode"]       = s["mode"]
                        all_history.append(entry)
                history = all_history
            else:
                history = db.get_search_history(sid_log)
                for entry in history:
                    entry["session_id"] = sid_log

            if not history:
                st.info("No searches recorded yet. Run a search in **🏥 SSE – Medical Records** first.")
            else:
                display_history = [
                    {
                        "Session":              h.get("session_id", "—"),
                        "Mode":                 h.get("mode", "—"),
                        "Trapdoor (truncated)": str(h["trapdoor"])[:32] + "…",
                        "Results Found":        h["results_count"],
                        "Searched At":          h["searched_at"],
                    }
                    for h in history
                ]
                st.dataframe(display_history, use_container_width=True, hide_index=True)
                st.markdown(f'<div class="table-info">📊 {len(history)} search log entries</div>', unsafe_allow_html=True)

                if len(history) > 1:
                    st.markdown("**📈 Results per search (chronological):**")
                    chart_data = {
                        "Search #": list(range(1, len(history) + 1)),
                        "Results":  [h["results_count"] for h in reversed(history)],
                    }
                    st.bar_chart(chart_data, x="Search #", y="Results", use_container_width=True)

    # ── Tab 5 : Pattern Words ─────────────────────────────────────────────────
    with tab5:
        st.markdown("""
        <div class="explorer-header">
            <h4>pattern_words table</h4>
            <p>Word → ciphertext pairs from the Deterministic Encryption demo. Identical words always produce identical ciphertexts.</p>
        </div>""", unsafe_allow_html=True)

        sessions_list   = db.get_all_sessions()
        pattern_sessions = [s for s in sessions_list if s["mode"] == "deterministic_pattern"]

        if not pattern_sessions:
            st.info("No pattern analysis sessions yet. Run the **🔢 Pattern Analysis** demo first.")
        else:
            sid_pat = st.selectbox(
                "Session",
                options=[s["id"] for s in pattern_sessions],
                format_func=lambda x: f"Session {x}",
                key="pat_sid",
            )
            words = db.load_pattern_words(sid_pat)

            if not words:
                st.info(f"No pattern words for session {sid_pat}.")
            else:
                palette   = ["#6c63ff", "#50fa7b", "#ffb86c", "#ff79c6", "#8be9fd"]
                ct_colors: Dict[str, str] = {}

                display_words = []
                for w in words:
                    ct = str(w["ciphertext"])
                    if ct not in ct_colors:
                        ct_colors[ct] = palette[len(ct_colors) % len(palette)]
                    display_words.append({
                        "Position":               w["position"] + 1,
                        "Word":                   w["word"],
                        "Ciphertext (truncated)": ct[:40] + "…",
                        "Ciphertext Group":       list(ct_colors.keys()).index(ct) + 1,
                    })

                st.dataframe(display_words, use_container_width=True, hide_index=True)
                st.markdown(
                    f'<div class="table-info">📊 {len(words)} word(s) · {len(ct_colors)} unique ciphertext(s)</div>',
                    unsafe_allow_html=True,
                )

                st.markdown("**🎨 Visual grouping — same colour = same ciphertext (same word):**")
                num_cols = min(len(words), 5)
                cols = st.columns(num_cols)
                for i, w in enumerate(words):
                    ct    = str(w["ciphertext"])
                    color = ct_colors[ct]
                    with cols[i % num_cols]:
                        st.markdown(
                            f'<div style="background:#0f0f1a;border:2px solid {color};border-radius:8px;'
                            f'padding:0.6rem;text-align:center;margin-bottom:0.5rem;">'
                            f'<span style="color:{color};font-weight:700;font-size:1rem;">{w["word"]}</span><br>'
                            f'<span style="color:#555;font-size:0.65rem;font-family:monospace;">#{w["position"]+1}</span>'
                            f'</div>',
                            unsafe_allow_html=True,
                        )

                st.info(
                    "💡 **Security leak:** Identical words share the same colour (ciphertext). "
                    "An attacker can deduce word frequencies without ever knowing the encryption key."
                )


# ══════════════════════════════════════════════════════════════════════════════
# Footer
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("---")
_db_status = "🗄️ MySQL connected" if DB_AVAILABLE else "⚠️ MySQL offline"
st.caption(f"🔐 Searchable Encryption Demo · Hackathon Project · AES-CBC + HMAC-SHA256 + PBKDF2 · {_db_status}")
