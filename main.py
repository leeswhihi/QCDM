import hashlib
import hmac
import secrets
import struct
import sys

class QCDM_Sonic:
    def __init__(self, key):
        self._key = key.encode()
        # 블록 크기 최적화 (CPU 캐시 친화적인 크기 고려)
        self.BLOCK_SIZE = 128 

    def _get_keystream_fast(self, seed_val, length):
        """
        [최적화 포인트 1] 반복문 제거
        기존: for 문을 돌며 카오스 수식을 수천 번 계산
        변경: 카오스 수식은 시드 생성용으로 '딱 한 번'만 실행 후,
              초고속 C언어 기반 함수인 SHAKE-256으로 스트림을 한방에 뽑아냄.
        """
        # 카오스 초기화 (단 1회 연산)
        r = 3.9999
        chaos = r * seed_val * (1 - seed_val)
        
        # 카오스 값을 바이트로 패킹하여 시드로 사용
        seed_bytes = struct.pack('d', chaos) 
        
        # 원하는 길이만큼의 난수를 C레벨 속도로 한 번에 생성
        return hashlib.shake_256(seed_bytes).digest(length)

    def encrypt(self, plaintext):
        # 1. Salt 생성
        salt = secrets.token_bytes(16)
        
        # [최적화 포인트 2] 키 스트레칭 횟수 조절
        # 보안과 속도의 타협점. 너무 느리면 사용성이 떨어짐 (20만회 -> 5만회)
        # *실제 상용환경에서는 보안 정책에 따라 조절 필요
        derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)
        
        # 패딩 (PKCS#7)
        data_bytes = plaintext.encode('utf-8')
        padding_len = self.BLOCK_SIZE - (len(data_bytes) % self.BLOCK_SIZE)
        padded_data = data_bytes + bytes([padding_len] * padding_len)
        data_len = len(padded_data)

        # 키 스트림 생성
        seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
        if seed_val == 0: seed_val = 0.987654321
        keystream = self._get_keystream_fast(seed_val, data_len)

        # [최적화 포인트 3] 거대 정수 XOR (The Big Int Trick)
        # for 문으로 byte ^ byte 하는 것은 파이썬에서 매우 느림.
        # 데이터를 통째로 하나의 거대한 숫자로 변환하여 CPU가 한 번에 처리하게 함.
        int_data = int.from_bytes(padded_data, 'big')
        int_keystream = int.from_bytes(keystream, 'big')
        
        # CPU 레벨의 고속 비트 연산
        int_cipher = int_data ^ int_keystream
        
        # 다시 바이트로 변환
        encrypted_bytes = int_cipher.to_bytes(data_len, 'big')

        # HMAC 서명
        signature = hmac.new(derived_key, salt + encrypted_bytes, hashlib.sha256).digest()
        
        # 결과 반환 (Hex 인코딩이 Base64보다 빠를 수 있음)
        return (salt + signature + encrypted_bytes).hex()

    def decrypt(self, ciphertext_hex):
        try:
            # 1. 데이터 파싱
            raw_data = bytes.fromhex(ciphertext_hex)
            salt = raw_data[:16]
            sig = raw_data[16:48]
            body = raw_data[48:]
            
            # 2. 키 재생성
            derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)
            
            # 3. 서명 검증 (상수 시간 비교 사용)
            expected_sig = hmac.new(derived_key, salt + body, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected_sig):
                raise ValueError("데이터 변조 감지됨")
                
            # 4. 키 스트림 생성
            seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
            if seed_val == 0: seed_val = 0.987654321
            keystream = self._get_keystream_fast(seed_val, len(body))
            
            # [최적화 포인트 3] 거대 정수 XOR 복호화
            int_body = int.from_bytes(body, 'big')
            int_keystream = int.from_bytes(keystream, 'big')
            
            int_plain = int_body ^ int_keystream
            padded_plain = int_plain.to_bytes(len(body), 'big')
            
            # 5. 패딩 제거
            padding_len = padded_plain[-1]
            return padded_plain[:-padding_len].decode('utf-8')
            
        except Exception as e:
            return f"Error: {str(e)}"

# --- 속도 측정 테스트 ---
if __name__ == "__main__":
    import time
    
    # 엄청 긴 텍스트 준비 (약 1MB)
    text = "Fastest Python Cipher " * 50000 
    key = "Speed_King"
    
    cipher = QCDM_Sonic(key)
    
    print(f"🚀 데이터 크기: {len(text)/1024:.2f} KB 암호화 시작...")
    
    start_time = time.time()
    enc = cipher.encrypt(text)
    end_time = time.time()
    
    print(f"⏱️ 암호화 소요 시간: {end_time - start_time:.4f}초")
    
    start_time = time.time()
    dec = cipher.decrypt(enc)
    end_time = time.time()
    
    print(f"⏱️ 복호화 소요 시간: {end_time - start_time:.4f}초")
    
    # 검증
    if dec == text:
        print("✅ 무결성 검증 완료: 완벽하게 복구되었습니다.")
    else:
        print("❌ 오류 발생")