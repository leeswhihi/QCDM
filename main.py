import hashlib
import base64
import os
import hmac

class QCDM_Fortress:
    def __init__(self, key):
        self.original_key = key.encode()

    def _derive_key(self, salt):
        """
        [방어막 3] 키 스트레칭 (PBKDF2)
        비밀번호에 소금(Salt)을 치고 10만 번 섞어서 해킹을 어렵게 만듭니다.
        """
        return hashlib.pbkdf2_hmac(
            'sha256', 
            self.original_key, 
            salt, 
            100000
        )

    def _logistic_map_generator(self, seed_val, length):
        """
        카오스 이론을 이용한 난수 생성기
        """
        nums = []
        x = seed_val
        r = 3.9999
        
        # 워밍업: 초기 패턴 제거
        for _ in range(50):
            x = r * x * (1 - x)
            
        for _ in range(length):
            x = r * x * (1 - x)
            # 0~255 사이 값으로 변환
            nums.append(int(x * 1000000) % 256)
        return nums

    def encrypt(self, plaintext):
        # [방어막 1] 솔트(Salt) 생성: 16바이트 무작위 난수
        salt = os.urandom(16)
        
        # 솔트를 섞어 강력한 파생 키 생성
        derived_key = self._derive_key(salt)
        
        # 파생 키를 이용해 카오스 시드값 결정 (0~1 사이 소수)
        seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
        if seed_val == 0: seed_val = 0.123456789

        text_bytes = plaintext.encode('utf-8')
        chaos_stream = self._logistic_map_generator(seed_val, len(text_bytes))
        
        encrypted_bytes = bytearray()
        
        # 암호화 로직 (XOR + 카오스)
        for i, byte in enumerate(text_bytes):
            cipher_byte = byte ^ chaos_stream[i]
            # 피드백 체이닝 (이전 블록의 영향)
            if i > 0:
                cipher_byte = cipher_byte ^ encrypted_bytes[i-1]
            encrypted_bytes.append(cipher_byte)
            
        # [방어막 2] HMAC 서명 (무결성 검증)
        # 암호문이 변조되었는지 확인하기 위한 도장
        signature = hmac.new(derived_key, salt + encrypted_bytes, hashlib.sha256).digest()
        
        # 최종 결과: [솔트(16)] + [서명(32)] + [암호문(가변)]
        final_pack = salt + signature + encrypted_bytes
        return base64.b64encode(final_pack).decode('utf-8')

    def decrypt(self, ciphertext):
        try:
            decoded = base64.b64decode(ciphertext)
            
            # 데이터 분리
            salt = decoded[:16]
            received_signature = decoded[16:48]
            encrypted_bytes = decoded[48:]
            
            # 키 재생성
            derived_key = self._derive_key(salt)
            
            # [방어막 2 작동] 서명 검증
            expected_signature = hmac.new(derived_key, salt + encrypted_bytes, hashlib.sha256).digest()
            
            # 타이밍 공격 방지를 위한 안전한 비교
            if not hmac.compare_digest(received_signature, expected_signature):
                raise ValueError("🚨 경고: 데이터가 누군가에 의해 변조되었습니다!")
            
            # 카오스 스트림 재생성
            seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
            if seed_val == 0: seed_val = 0.123456789
            chaos_stream = self._logistic_map_generator(seed_val, len(encrypted_bytes))
            
            decrypted_bytes = bytearray()
            
            for i in range(len(encrypted_bytes)):
                cipher_byte = encrypted_bytes[i]
                
                # 피드백 해제
                temp_byte = cipher_byte
                if i > 0:
                    temp_byte = temp_byte ^ encrypted_bytes[i-1]
                
                original_byte = temp_byte ^ chaos_stream[i]
                decrypted_bytes.append(original_byte)
                
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            return f"복호화 실패: {str(e)}"

# --- 해킹 시뮬레이션 ---
if __name__ == "__main__":
    key = "My_Super_Secret_Key"
    msg = "Attack at dawn!"
    
    cipher = QCDM_Fortress(key)
    
    # 1. 정상적인 암호화
    enc_str = cipher.encrypt(msg)
    print(f"🔒 1차 암호문: {enc_str[:30]}...")
    
    # 2. [방어막 1 테스트] 같은 내용 다시 암호화 -> 결과가 달라야 함
    enc_str_2 = cipher.encrypt(msg)
    print(f"🔒 2차 암호문: {enc_str_2[:30]}... (내용은 같지만 암호문은 다름!)")
    
    # 3. [방어막 2 테스트] 해커의 데이터 변조 시도
    print("\n😈 해커가 암호문을 가로채서 조작 중...")
    raw_data = bytearray(base64.b64decode(enc_str))
    raw_data[-1] = raw_data[-1] ^ 0xFF  # 마지막 바이트를 강제로 변경
    modified_enc_str = base64.b64encode(raw_data).decode('utf-8')
    
    # 복호화 시도
    result = cipher.decrypt(modified_enc_str)
    print(f"결과: {result}")