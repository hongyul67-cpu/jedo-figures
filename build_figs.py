# 교과서 도해 → 암호화 배포본 만들기
#
#   python build_figs.py --src <압축된 이미지 폴더> --pw <교사용 암호>
#
# 왜 암호화하나:
#   교과서 그림은 출판사 저작물이다. 화면만 자바스크립트로 가리면
#   주소를 아는 사람은 그림 파일을 그대로 받아 갈 수 있다.
#   그래서 파일 자체를 AES-GCM 으로 암호화해 올리고,
#   코드가 맞을 때만 브라우저 안에서 풀어 보여 준다.
#   (links-master 의 tools.enc, 반도체 도구의 bank.enc 와 같은 방식)
#
# 암호는 두 종류:
#   교사용 - 문구형, 만료 없음
#   학생용 - 8자리 숫자, 그 주 월요일부터 7일
#   시크릿·기준일·접두어는 _weekly/secret.json 을 그대로 쓴다.
#   그래서 다른 도구와 같은 코드로 열리고, 다시 빌드해도 코드가 바뀌지 않는다.
import io, os, re, json, base64, argparse, sys, secrets
from datetime import date
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "_weekly"))
import weekly

ITER = 200_000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="압축된 이미지와 manifest.json 이 있는 폴더")
    ap.add_argument("--pw", required=True, help="교사용 암호 (만료 없음)")
    a = ap.parse_args()

    cfg = weekly.load()
    start = date.fromisoformat(cfg["epoch"])
    nweeks = cfg["weeks"]

    man = json.load(io.open(os.path.join(a.src, "manifest.json"), encoding="utf-8"))
    # 주제 목록(단원·절)도 함께 담는다 — 그림 문제에서 보기로 쓴다
    tpath = os.path.join(a.src, "..", "topics.json")
    topics = json.load(io.open(tpath, encoding="utf-8")) if os.path.exists(tpath) else {}
    # 그림별 문제은행 — 그림을 직접 보고 만든 문제 (없어도 된다)
    bpath = os.path.join(a.src, "..", "seedbank.json")
    bank = json.load(io.open(bpath, encoding="utf-8")) if os.path.exists(bpath) else []
    outdir = os.path.join(HERE, "enc")
    os.makedirs(outdir, exist_ok=True)

    # 1) 그림 하나하나를 같은 내용키(CK)로 암호화
    CK = secrets.token_bytes(32)
    aes = AESGCM(CK)
    total = 0
    print("  그림 암호화 %d장 ..." % len(man), end="", flush=True)
    for r in man:
        raw = open(os.path.join(a.src, r["f"]), "rb").read()
        nonce = secrets.token_bytes(12)
        blob = nonce + aes.encrypt(nonce, raw, None)
        open(os.path.join(outdir, r["f"] + ".enc"), "wb").write(blob)
        total += len(blob)
    print(" 완료 (%.1f MB)" % (total / 1048576))

    # 2) 목록(어느 단원 몇 쪽인지)도 함께 암호화 — 목차만 봐도 교재가 드러나므로
    man_raw = json.dumps({"figs": man, "topics": topics, "bank": bank},
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    n2 = secrets.token_bytes(12)
    man_blob = n2 + aes.encrypt(n2, man_raw, None)

    # 3) 암호마다 CK 를 감싼다 (salt 공유 → 해제 시 PBKDF2 1회)
    salt = secrets.token_bytes(16)
    MASTER = base64.b64decode(cfg["secret"])          # 도구 공용 — 새로 만들지 않는다

    def derive(p):
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                          salt=salt, iterations=ITER).derive(p.encode("utf-8"))

    def wrap(p, info):
        iv = secrets.token_bytes(12)
        blob = AESGCM(derive(p)).encrypt(iv, json.dumps(info).encode("utf-8"), None)
        return {"iv": base64.b64encode(iv).decode(),
                "blob": base64.b64encode(blob).decode()}

    ck_b64 = base64.b64encode(CK).decode()
    keys = [wrap(a.pw, {"ck": ck_b64, "exp": None, "role": "teacher", "label": "교사용",
                        "ms": base64.b64encode(MASTER).decode(),
                        "epoch": start.isoformat(), "weeks": nweeks,
                        "prefix": cfg["prefix"]})]
    sheet = weekly.weeks(cfg)
    print("  키 감싸기 교사용 1개 + 학생용 %d주치 ..." % nweeks, end="", flush=True)
    for n, d0, d1, c in sheet:
        keys.append(wrap(c, {"ck": ck_b64, "nbf": d0.isoformat(), "exp": d1.isoformat(),
                             "role": "student", "label": d0.isoformat()}))
    print(" 완료")
    secrets.SystemRandom().shuffle(keys)

    io.open(os.path.join(HERE, "figs.json"), "w", encoding="utf-8").write(json.dumps({
        "v": 1, "cipher": "AES-GCM", "count": len(man),
        "kdf": {"name": "PBKDF2", "hash": "SHA-256", "iter": ITER,
                "salt": base64.b64encode(salt).decode()},
        "manifest": base64.b64encode(man_blob).decode(),
        "keys": keys,
    }))

    cur = weekly.this_week(cfg)
    print("")
    print("  그림 %d장 · enc %.1f MB · 그림문제 %d문항" % (len(man), total / 1048576, len(bank)))
    print("  교사용 암호 : %s   (만료 없음)" % a.pw)
    if cur:
        print("  이번 주 코드: %s %s   (%s ~ %s)" % (cur[3][:4], cur[3][4:], cur[1], cur[2]))


if __name__ == "__main__":
    main()
