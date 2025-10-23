import os, re, io, sys, mmap, time, html, joblib, unicodedata, json
import numpy as np
from urllib.parse import urlparse
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.calibration import CalibratedClassifierCV
from sklearn.decomposition import TruncatedSVD
from sklearn.ensemble import IsolationForest

# UTF-8 stdout
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ===== 경로/설정 =====
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAL_MODEL_PATH = os.path.join(BASE_DIR, "calibrated_model.pkl")
IFOREST_MODEL_PATH = os.path.join(BASE_DIR, "iforest_model.pkl")



# --- 정규화 ---
_SQL_COMMENTS_RE = re.compile(r"(--[^\r\n]*|/\*.*?\*/|#[^\r\n]*)", re.DOTALL|re.IGNORECASE)
_WHITESPACE_RE   = re.compile(r"[\u0000-\u001F\u007F\u0085\u00A0\u1680\u2000-\u200F\u2028-\u202F\u205F\u3000]+")
_HTML_TAG_WS_RE  = re.compile(r"\s+")
_PCT_WS_RE       = re.compile(r"%0[aAdD]|%09|%0b|%0c|%a0", re.IGNORECASE)
HOMO = str.maketrans({"А":"A","В":"B","Е":"E","М":"M","Н":"H","О":"O","Р":"P","С":"C","Т":"T","Х":"X", "а":"a","е":"e","о":"o","р":"p","с":"c","х":"x","і":"i","ї":"i","ј":"j"})

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

# --- 퍼지 패턴 ---
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

# --- 벡터라이저 ---
vec = HashingVectorizer(n_features=2**20, alternate_sign=False, norm='l2', analyzer='char_wb', ngram_range=(3,5))

# --- 파싱 & 라벨링 ---
def parse_line(line: str):
    m = re.search(r'(?:^|")([A-Z]{3,10})\s+(.+?)\s+HTTP/\d\.\d', line, flags=re.DOTALL)
    if not m: return "", ""
    uri = m.group(2).replace("\r","").replace("\n","")
    parsed = urlparse(uri)
    return parsed.path or "", parsed.query or ""
    

def parse_jsonl_line(line: str):
    try:
        data = json.loads(line)
        method = data.get("method", "GET")
        path = data.get("path", "")
        param_key = data.get("param", "")
       
        payload_example = "vuln_test"
        query = f"{param_key}={payload_example}"

        # 기존 파서가 이해할 수 있는 웹 서버 로그 형식으로 변환
        formatted_line = f'"{method} {path}?{query} HTTP/1.1"'
        return parse_line(formatted_line)
    except (json.JSONDecodeError, AttributeError):
        return "", ""

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

# ===== 분석 파이프라인 =====
def analyze_single_file(filepath):
    try:
        cal_clf = joblib.load(CAL_MODEL_PATH)
        iforest, svd = joblib.load(IFOREST_MODEL_PATH)
    except FileNotFoundError:
        print("❌ 모델 파일(calibrated_model.pkl 또는 iforest_model.pkl)을 찾을 수 없습니다.")
        print("   먼저 train.py를 실행하여 모델을 학습시키세요.")
        sys.exit(1)

    results = []
    
   
    is_jsonl = filepath.endswith('.jsonl')

    for line in iter_lines_mmap(filepath):
        if is_jsonl:
            path, query = parse_jsonl_line(line)
        else:
            path, query = parse_line(line)

        if not path and not query: continue
        
        rec = (path or "") + (('?' + query) if query else '')
        
        rule_prediction = rule_based_label(path, query)

        if rule_prediction != "normal":
            prediction = rule_prediction
        else:
            prediction = cal_clf.predict(vec.transform([rec]))[0]

        vectorized_rec = vec.transform([rec])
        reduced_rec = svd.transform(vectorized_rec)
        anomaly_score = iforest.decision_function(reduced_rec)[0]
        
        results.append({
            "original_log": line.strip(),
            "url": rec,
            "prediction": prediction,
            "anomaly_score": float(anomaly_score),
            "status": "analyzed"
        })
    return results

# ===== 메인 실행 로직 =====
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("❌ 사용법: python asdfg.py <분석할_로그파일_경로>")
        sys.exit(1)
        
    target_file = sys.argv[1]
    if not os.path.exists(target_file):
        print(f"❌ 파일을 찾을 수 없습니다: {target_file}")
        sys.exit(1)
        
    analysis_results = analyze_single_file(target_file)
    print(json.dumps(analysis_results, indent=2, ensure_ascii=False))