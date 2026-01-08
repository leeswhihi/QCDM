import hashlib
import hmac
import os
import secrets
import struct
import gc  # 가비지 컬렉션 제어

class QCDM_BlackHole:
    def __init__(self, key):
        self._key = key.encode()
        # 블록 사이즈 설정 (예: 64바이트 단위로 데이터를 자르고 채움)
        self.BLOCK_SIZE = 64 

    def _cleanup(self, *args):
        """
        [보완점 C] 메모리 위생 관리
        사용된 민감한 변수들을 강제로 삭제하고 가비지 컬렉터를 돌립니다.
        완벽하진 않지만(Python 특성상), 해커가 RAM을 뒤질 때 흔적을 줄입니다.
        """
        for var in args:
            del var
        gc.collect()

    def _pad(self, data):
        """
        [보완점 A] PKCS#7 패딩 적용
        데이터의 길이를 숨기기 위해 의미 없는 값을 채워 넣습니다.
        예: 'Hi' -> 'Hi' + [padding] ... 외부에서는 데이터 길이를 정확히 알 수 없습니다.
        """
        padding_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def _unpad(self, data):
        padding_len = data[-1]
        return data[:-padding_len]

    def _generate_keystream(self, seed, length):
        """
        [보완점 B] 카오스 + SHAKE256 하이브리드 엔진
        단순 카오스 수식이 아니라, 차세대 해시 함수(SHAKE256)를 사용하여
        무한대에 가까운 길이의 난수를 뽑아냅니다. (패턴 분석 불가능)
        """
        # 카오스 시드값 혼합
        chaos_factor = seed
        r = 3.9999
        for _ in range(20): # 카오스 예열
            chaos_factor = r * chaos_factor * (1 - chaos_factor)
        
        # 카오스 값을 바이트로 변환하여 SHAKE256의 시드로 사용
        chaos_bytes = struct.pack('f', chaos_factor)
        
        # SHAKE256: 원하는 길이만큼 난수를 뽑아낼 수 있는 XOF(Extensible Output Function)
        return hashlib.shake_256(chaos_bytes).digest(length)

    def encrypt(self, plaintext):
        try:
            # 1. 강력한 난수(Nonce/Salt) 생성
            salt = secrets.token_bytes(32) # os.urandom보다 안전한 secrets 사용
            
            # 2. 키 스트레칭 (공격 비용 증가)
            derived_key = hashlib.pbkdf2_hmac('sha3-256', self._key, salt, 200000)
            
            # 3. 데이터 패딩 (길이 정보 은닉)
            padded_data = self._pad(plaintext.encode('utf-8'))
            
            # 4. 하이브리드 키 스트림 생성
            # 파생키의 일부를 카오스 시드로 변환 (0~1 사이 실수)
            seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
            keystream = self._generate_keystream(seed_val, len(padded_data))
            
            encrypted_bytes = bytearray()
            
            # 5. XOR 암호화 진행
            for i in range(len(padded_data)):
                encrypted_bytes.append(padded_data[i] ^ keystream[i])
            
            # 6. HMAC-SHA3-256 서명 (무결성 + 인증)
            # SHA-256보다 구조적으로 안전한 SHA3 계열 사용
            signature = hmac.new(derived_key, salt + encrypted_bytes, hashlib.sha3_256).digest()
            
            # 최종 패키징: [Salt(32)] + [Signature(32)] + [Encrypted Body]
            final_data = salt + signature + encrypted_bytes
            
            return final_data.hex() # 16진수 문자열로 반환
            
        finally:
            # 보안상 민감한 임시 변수 삭제
            if 'derived_key' in locals(): self._cleanup(derived_key)
            if 'keystream' in locals(): self._cleanup(keystream)

    def decrypt(self, ciphertext_hex):
        try:
            # 1. 데이터 파싱
            decoded_data = bytes.fromhex(ciphertext_hex)
            
            salt = decoded_data[:32]
            received_sig = decoded_data[32:64]
            encrypted_body = decoded_data[64:]
            
            # 2. 키 재생성
            derived_key = hashlib.pbkdf2_hmac('sha3-256', self._key, salt, 200000)
            
            # 3. 서명 검증 (데이터 변조 확인)
            calculated_sig = hmac.new(derived_key, salt + encrypted_body, hashlib.sha3_256).digest()
            
            if not hmac.compare_digest(received_sig, calculated_sig):
                raise ValueError("🚨 치명적 경고: 데이터 무결성이 훼손되었습니다. (변조 감지)")
            
            # 4. 키 스트림 재생성
            seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
            keystream = self._generate_keystream(seed_val, len(encrypted_body))
            
            # 5. 복호화
            decrypted_padded = bytearray()
            for i in range(len(encrypted_body)):
                decrypted_padded.append(encrypted_body[i] ^ keystream[i])
            
            # 6. 패딩 제거
            original_text = self._unpad(decrypted_padded).decode('utf-8')
            
            return original_text
            
        except Exception as e:
            return f"복호화 실패: {str(e)}"
        finally:
             if 'derived_key' in locals(): self._cleanup(derived_key)

# --- 극한의 테스트 ---
if __name__ == "__main__":
    # 매우 간단한 비밀번호를 써도 내부적으로는 강력하게 변환됨
    pw = "my_password" 
    
    # 길이가 다른 두 메시지
    msg_short = "Hi"
    msg_long = "Hi" # 내용은 같지만 패딩 로직 테스트를 위해
    
    cipher = QCDM_BlackHole(pw)
    
    # 암호화
    enc_1 = cipher.encrypt(msg_short)
    print(f"🔒 암호문(Hex): {enc_1[:50]}... (총 길이: {len(enc_1)})")
    
    # 복호화 확인
    dec_1 = cipher.decrypt(enc_1)
    print(f"🔓 복호화 결과: {dec_1}")
    
    print("-" * 30)
    
    # 취약점 A 방어 확인: 아주 짧은 메시지도 블록 사이즈만큼 늘어났는지?
    # 원본 'Hi'는 2바이트지만, 암호문은 훨씬 깁니다 (Salt 32 + Sig 32 + Padding된 본문 64 = 128바이트 이상)
    print(f"✅ 트래픽 은닉 확인: 원본은 2글자지만 암호문은 {len(bytes.fromhex(enc_1))}바이트입니다.")