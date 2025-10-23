import os, re, io, sys, glob, mmap, time, html, random, string, joblib, unicodedata, json
import numpy as np, pandas as pd
from datetime import datetime
from urllib.parse import urlparse, quote
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import IsolationForest
from collections import Counter

# UTF-8 stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ========= 경로/설정 =========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

BASE_MODEL_PATH = os.path.join(BASE_DIR, "sgd_model.pkl")
CAL_MODEL_PATH = os.path.join(BASE_DIR, "calibrated_model.pkl")
IFOREST_MODEL_PATH = os.path.join(BASE_DIR, "iforest_model.pkl")

# ========= 정규화 =========
_SQL_COMMENTS_RE = re.compile(r"(--[^\r\n]*|/\*.*?\*/|#[^\r\n]*)", re.DOTALL|re.IGNORECASE)
_WHITESPACE_RE   = re.compile(r"[\u0000-\u001F\u007F\u0085\u00A0\u1680\u2000-\u200F\u2028-\u202F\u205F\u3000]+")
_HTML_TAG_WS_RE  = re.compile(r"\s+")
_PCT_WS_RE       = re.compile(r"%0[aAdD]|%09|%0b|%0c|%a0", re.IGNORECASE)
HOMO = str.maketrans({"А":"A","В":"B","Е":"E","М":"M","Н":"H","О":"O","Р":"P","С":"C","Т":"T","Х":"X",
                      "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","і":"i","ї":"i","ј":"j"})

def multi_unquote(s: str, rounds: int = 3) -> str:
    from urllib.parse import unquote
    x = s
    for _ in range(rounds):
        y = unquote(x)
        if y == x: break
        x = y
    return x

def canonicalize(s: str) -> str:
    if not s: return ""
    s = unicodedata.normalize("NFKC", s).translate(HOMO)
    s = multi_unquote(s, 3)
    s = html.unescape(s)
    s = _PCT_WS_RE.sub(" ", s)
    s = _SQL_COMMENTS_RE.sub(" ", s)
    s = _WHITESPACE_RE.sub(" ", s)
    s = _HTML_TAG_WS_RE.sub(" ", s)
    return s.strip().lower()

# ========= 퍼지 패턴 =========
def fuzzy_keyword(w: str) -> str:
    junk = r"(?:/\*.*?\*/|%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\s|\\W){0,3}"
    return "".join([re.escape(ch)+junk for ch in w])

RAW_STRICT = {
    "sql_injection":[
        r"\bselect\b.{0,80}\bfrom\b", r"\binsert\b.{0,60}\binto\b", r"\bupdate\b.{0,60}\bset\b",  r"\bdelete\b.{0,60}\bfrom\b",
        r"\bdrop\b.{0,40}\b(table|database)\b", r"\bcreate\b.{0,40}\b(table|database)\b", r"\btruncate\b.{0,20}\btable\b", r"\bunion\s+(?:all\s+)?select\b",
        r"(?:--|#|/\*.*?\*/)\s*$", r"(?:;|\s)%0a|%0d", r"(?:'|\")\s*(?:or|and)\s*1\s*=\s*1", r"\s+(?:or|and)\s+", r"\b1\s*=\s*1\b",
        r"\b(information_schema|performance_schema|mysql\.user|pg_catalog|sysobjects|v\$version)\b",
        r"\b(@@version|user\(\)|database\(\)|schema_name|group_concat|concat(?:_ws)?)\s*\(",
        r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(", r"\b(extractvalue|updatexml)\s*\(",
        r"\b(load_file|into\s+(?:out|dump)file)\b", r"\bexec(?:ute)?\b|\b(?:master\.)?xp_cmdshell\b", r"0x[0-9a-fA-F]{4,}", r"%27|%22|%2d%2d|%23|%20(or|and)%20", r"\bchar\s*\(",
        r"\[\$(ne|gt|lt|gte|lte|in|nin)\]=", r"\$where\s*:", r"\b(contains|starts-with|substring-before|substring-after)\s*\(",
        r"following-sibling|ancestor-or-self",
    ],
    "xss_attack":[
        r"<\s*script\b", r"<\s*/\s*script\s*>", r"<script\s+src\s*=", r"\bon[a-z]{2,}\s*=", r"<\s*(img|svg|iframe|body|video|audio|embed|object|picture)\b[^>]*>",
        r"\b(javascript|vbscript|data)\s*:", r"data\s*:\s*text/html\s*;\s*base64", r"&#x[0-9a-fA-F]+;",
        r"\b(alert|prompt|confirm|eval)\s*\(", r"document\.(cookie|location|domain|write)",
        r"window\.location", r"String\.fromCharCode\s*\(", r"localStorage|sessionStorage", r"style\s*=\s*['\"][^'\"]*expression\s*\(", r"@import",
        r"\{\{.*\}\}",   r"<\%.*\%>",     r"\#\{.*\}",
        r"\b(ontoggle|onfocus|onanimationend)\s*=", r"\b(formaction)\s*=",
    ]
}

RAW_FUZZY = { "sql_injection": [ rf"\b{fuzzy_keyword('union')}\s*(?:{fuzzy_keyword('all')}\s*)?{fuzzy_keyword('select')}\b", rf"{fuzzy_keyword('select')}.{{0,80}}{fuzzy_keyword('from')}", rf"{fuzzy_keyword('insert')}.{{0,60}}{fuzzy_keyword('into')}", rf"{fuzzy_keyword('update')}.{{0,60}}{fuzzy_keyword('set')}", rf"{fuzzy_keyword('delete')}.{{0,60}}{fuzzy_keyword('from')}", rf"{fuzzy_keyword('sleep')}\s*\(", rf"{fuzzy_keyword('pg_sleep')}\s*\(", rf"{fuzzy_keyword('benchmark')}\s*\(", rf"{fuzzy_keyword('extractvalue')}\s*\(", rf"{fuzzy_keyword('updatexml')}\s*\(", rf"(?:'|\")\s*(?:{fuzzy_keyword('or')}|{fuzzy_keyword('and')})\s*1\s*=\s*1", r"\b1\s*=\s*1\b", r"0x[0-9a-fA-F]{4,}", r"%27|%22|%2d%2d|%23|%20(?:or|and)%20", r"\bchar\s*\(" ], "xss_attack": [ rf"<\s*{fuzzy_keyword('script')}\b", rf"<\s*/\s*{fuzzy_keyword('script')}\s*>", rf"{fuzzy_keyword('on')}[a-z]{{2,}}\s*=", r"<\s*(img|svg|iframe|body|video|audio|embed|object|picture)\b[^>]*>", rf"\b({fuzzy_keyword('javascript')}|{fuzzy_keyword('vbscript')}|{fuzzy_keyword('data')})\s*:", r"data\s*:\s*text/html\s*;\s*base64", r"&#x[0-9a-fA-F]+;", rf"\b({fuzzy_keyword('alert')}|{fuzzy_keyword('prompt')}|{fuzzy_keyword('confirm')}|{fuzzy_keyword('eval')})\s*\(", r"document\.(cookie|location|domain|write)", r"window\.location", rf"{fuzzy_keyword('String')}\s*\.\s*{fuzzy_keyword('fromCharCode')}\s*\(", r"localStorage|sessionStorage", r"style\s*=\s*['\"][^'\"]*expression\s*\(", r"@import" ] }
PAT_STRICT = {k:[re.compile(p, re.IGNORECASE|re.DOTALL) for p in v] for k,v in RAW_STRICT.items()}
PAT_FUZZY  = {k:[re.compile(p, re.IGNORECASE|re.DOTALL) for p in v] for k,v in RAW_FUZZY.items()}

# ========= 벡터라이저 =========
vec = HashingVectorizer(n_features=2**20, alternate_sign=False, norm='l2',
                        analyzer='char_wb', ngram_range=(3,5))

# ========= 파싱 & 라벨링 =========
def parse_line(line: str):
    m = re.search(r'(?:^|")([A-Z]{3,10})\s+(.+?)\s+HTTP/\d\.\d', line, flags=re.DOTALL)
    if not m: return "", ""
    uri = m.group(2).replace("\r","").replace("\n","")
    parsed = urlparse(uri)
    return parsed.path or "", parsed.query or ""


def parse_and_label_jsonl(line: str):
    try:
        data = json.loads(line)
        
        # 1. 라벨링: detection 필드를 직접 사용
        detection = data.get("detection", "")
        if "XSS" in detection:
            label = "xss_attack"
        elif "SQL" in detection:
            label = "sql_injection"
        else:
            label = "normal"

        # 2. URL 재구성 (AI 학습용)
        path = data.get("path", "")
        param_key = data.get("param", "")
        # 실제 payload는 없으므로 형태만 만듦 (학습 데이터의 일관성 유지)
        payload_example = "vuln_test" 
        query = f"{param_key}={payload_example}"
        url = (path or "") + (('?' + query) if query else '')

        return url, label
        
    except (json.JSONDecodeError, AttributeError):
        return None, None

def iter_lines_mmap(filepath):
    with open(filepath,'rb') as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        for raw in iter(mm.readline, b""):
            if not raw: break
            yield raw.decode('utf-8', errors='ignore').strip()
        mm.close()

def rule_based_label(path, query):
    full = canonicalize((path or "") + (("?" + query) if query else ""))
    for rgx in PAT_STRICT["xss_attack"]:
        if rgx.search(full): return "xss_attack"
    for rgx in PAT_FUZZY["xss_attack"]:
        if rgx.search(full): return "xss_attack"
    q = canonicalize(query or "")
    if q:
        for rgx in PAT_STRICT["sql_injection"]:
            if rgx.search(q): return "sql_injection"
        for rgx in PAT_FUZZY["sql_injection"]:
            if rgx.search(q): return "sql_injection"
    return "normal"

# ========= 학습 파이프라인 =========
if __name__ == '__main__':
    print("🚀 AI 모델 학습을 시작합니다...")
    
    log_files = glob.glob(os.path.join(LOG_DIR, '*.log')) + \
                glob.glob(os.path.join(LOG_DIR, '*.json')) + \
                glob.glob(os.path.join(LOG_DIR, '*.jsonl'))

    if not log_files:
        print(f"❌ '{LOG_DIR}'에서 처리할 로그 파일을 찾을 수 없습니다. 학습을 중단합니다.")
        sys.exit(1)

    print(f"📄 총 {len(log_files)}개의 로그 파일을 사용합니다.")
    all_texts, all_labels = [], []
    for fp in log_files:
        print(f"  - 처리 중: {os.path.basename(fp)}")
        
        is_jsonl = fp.endswith('.jsonl')

        for line in iter_lines_mmap(fp):
           
            if is_jsonl:
                rec, lbl = parse_and_label_jsonl(line)
                if not rec: # 파싱 실패 시 건너뛰기
                    continue
            else: # 기존 .log, .json 파일 처리
                path, query = parse_line(line)
                if not path and not query:
                    continue
                rec = (path or "") + (('?' + query) if query else '')
                lbl = rule_based_label(path, query)

            all_texts.append(rec)
            all_labels.append(lbl)

    if not all_texts:
        print("❌ 모든 파일에서 유효한 로그를 파싱하지 못했습니다. 학습을 중단합니다.")
        sys.exit(1)

    print(f"✅ 총 {len(all_texts):,}개의 로그 항목 라벨링 완료")
    
    MAX_SAMPLES_FOR_TRAINING = 200_000 
    n_total = len(all_texts)
    
    if n_total > MAX_SAMPLES_FOR_TRAINING:
        print(f"\n🧠 (메모리 최적화) 전체 {n_total:,}개 중 {MAX_SAMPLES_FOR_TRAINING:,}개만 무작위로 샘플링하여 학습을 진행합니다...")
        sample_indices = np.random.choice(n_total, MAX_SAMPLES_FOR_TRAINING, replace=False)
        texts_to_train = [all_texts[i] for i in sample_indices]
        labels_to_train = [all_labels[i] for i in sample_indices]
    else:
        print("\n🧠 (전체 데이터 사용) 데이터 양이 충분하여 전체 데이터를 사용하여 학습을 진행합니다...")
        texts_to_train = all_texts
        labels_to_train = all_labels
    
    print("📊 샘플링된 데이터 레이블 분포:"); print(pd.Series(labels_to_train).value_counts().to_string())
    
    print("\n🔡 벡터화 중(HashingVectorizer: char_wb 3~5-gram)...")
    X = vec.transform(texts_to_train); y = np.array(labels_to_train)

    print("💪 기본 모델(SGDClassifier) 학습...")
    base_clf = SGDClassifier(loss='log_loss', max_iter=1000, tol=1e-3).fit(X, y)
    joblib.dump(base_clf, BASE_MODEL_PATH); print(f"  - 모델 저장: {BASE_MODEL_PATH}")

    print("🎯 확률 보정(CalibratedClassifierCV)...")
    vc = pd.Series(y)
    min_samples = 0
    if not vc.empty:
      class_counts = vc.value_counts()
      if not class_counts.empty:
        min_samples = class_counts.min()

    if min_samples < 2:
        print(f"⚠️ 일부 클래스 샘플 부족(min={min_samples}) → 보정 생략, 기본 모델로 대체 저장")
        joblib.dump(base_clf, CAL_MODEL_PATH)
    else:
        cv_folds = min(max(2, int(min_samples)), 5)
        print(f"  - 자동 설정 cv={cv_folds}")
        cal_clf = CalibratedClassifierCV(base_clf, method='sigmoid', cv=cv_folds).fit(X, y)
        joblib.dump(cal_clf, CAL_MODEL_PATH)
    print(f"  - 보정(또는 대체) 모델 저장: {CAL_MODEL_PATH}")

    print("🌲 IsolationForest(이상치 탐지) 학습...")
    n_components = min(50, X.shape[1] - 1 if X.shape[1] > 1 else 1)
    svd = TruncatedSVD(n_components=n_components, random_state=42)
    X_red = svd.fit_transform(X)
    iforest = IsolationForest(n_estimators=50, contamination=0.01, random_state=42).fit(X_red)
    joblib.dump((iforest, svd), IFOREST_MODEL_PATH); print(f"  - 이상치 모델 저장: {IFOREST_MODEL_PATH}")

    print("\n✅ 모든 모델 학습 및 저장 완료!")
    print("     • 분류기: sgd_model.pkl, calibrated_model.pkl")
    print("     • 이상치: iforest_model.pkl (SVD 포함)")