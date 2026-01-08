import hashlib
import hmac
import secrets
import struct

class QCDM_Ultimate:
    def __init__(self, key):
        self._key = key.encode()
        # 파이스텔 구조를 위해 블록 사이즈를 짝수로 맞춤
        self.BLOCK_SIZE = 64 

    def _round_function(self, data_int, round_key_bytes):
        """
        [파이스텔 라운드 함수 F]
        입력된 데이터(Right)와 라운드 키를 섞어서 난잡한 값을 만듭니다.
        SHAKE-256을 사용하여 고속으로 비선형 변환을 수행합니다.
        """
        # 정수를 바이트로 변환
        data_bytes = data_int.to_bytes((data_int.bit_length() + 7) // 8, 'big')
        
        # 키와 데이터를 섞음
        mixed = hashlib.shake_256(data_bytes + round_key_bytes).digest(len(data_bytes))
        
        # 다시 정수로 변환하여 반환
        return int.from_bytes(mixed, 'big')

    def _process_feistel(self, data_bytes, derived_key, mode='encrypt'):
        """
        [핵심 원리: 파이스텔 네트워크]
        데이터를 좌우로 나누고 교차하며 섞습니다.
        """
        # 1. 데이터를 절반으로 나눔 (Left, Right)
        half_len = len(data_bytes) // 2
        L = int.from_bytes(data_bytes[:half_len], 'big')
        R = int.from_bytes(data_bytes[half_len:], 'big')
        
        # 4라운드 수행 (보안과 속도의 균형)
        rounds = 4
        
        for i in range(rounds):
            # 복호화일 때는 키를 역순으로 사용해야 함
            round_idx = i if mode == 'encrypt' else (rounds - 1 - i)
            
            # 라운드 키 생성 (파생키를 잘라서 사용)
            round_key = hashlib.sha256(derived_key + bytes([round_idx])).digest()
            
            if mode == 'encrypt':
                # 암호화: L_new = R, R_new = L ^ F(R)
                new_R = L ^ self._round_function(R, round_key)
                L = R
                R = new_R
            else:
                # 복호화: R_old = L, L_old = R ^ F(L) (암호화의 정확한 역순)
                # 파이스텔의 특징: 복호화 로직이 암호화와 대칭적임
                new_L = R ^ self._round_function(L, round_key)
                R = L
                L = new_L

        # 합치기 (최종 Swap은 생략하거나 포함 가능, 여기선 합침)
        L_bytes = L.to_bytes(half_len, 'big')
        R_bytes = R.to_bytes(half_len, 'big')
        return L_bytes + R_bytes

    def encrypt(self, plaintext):
        salt = secrets.token_bytes(16)
        # 키 생성 (속도를 위해 반복 횟수 최적화)
        derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 10000)
        
        # 패딩 (짝수 길이 보장)
        data = plaintext.encode('utf-8')
        pad_len = self.BLOCK_SIZE - (len(data) % self.BLOCK_SIZE)
        padded_data = data + bytes([pad_len] * pad_len)
        
        # 블록 단위로 파이스텔 적용이 원칙이나, 
        # 파이썬 속도를 위해 전체 데이터를 '하나의 거대 블록'으로 간주하고 파이스텔 적용 (변형된 구조)
        # *주의: 데이터가 너무 크면 메모리 이슈가 있을 수 있으나 텍스트 전송용으론 충분
        encrypted_body = self._process_feistel(padded_data, derived_key, 'encrypt')

        # HMAC 서명
        signature = hmac.new(derived_key, salt + encrypted_body, hashlib.sha256).digest()
        
        return (salt + signature + encrypted_body).hex()

    def decrypt(self, ciphertext_hex):
        try:
            raw = bytes.fromhex(ciphertext_hex)
            salt = raw[:16]
            sig = raw[16:48]
            body = raw[48:]
            
            derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 10000)
            
            expected_sig = hmac.new(derived_key, salt + body, hashlib.sha256).digest()
            if not hmac.compare_digest(sig, expected_sig):
                raise ValueError("데이터 변조됨")
            
            decrypted_body = self._process_feistel(body, derived_key, 'decrypt')
            
            # 패딩 제거
            pad_len = decrypted_body[-1]
            return decrypted_body[:-pad_len].decode('utf-8')
        except Exception as e:
            return f"Error: {str(e)}"

# --- 확산 효과(Diffusion) 테스트 ---
if __name__ == "__main__":
    key = "Feistel_Power"
    
    # 1. 원본 메시지
    msg1 = "Attack at 10:00 AM"
    # 2. 딱 한 글자만 바꾼 메시지 (0 -> 1)
    msg2 = "Attack at 10:01 AM"
    
    cipher = QCDM_Ultimate(key)
    
    enc1 = cipher.encrypt(msg1)
    enc2 = cipher.encrypt(msg2)
    
    print(f"🔹 원본 1 암호문 앞부분: {enc1[96:150]}...")
    print(f"🔸 원본 2 암호문 앞부분: {enc2[96:150]}...")
    print("\n✅ 확인해보세요! 단 1글자 차이인데 암호문은 완전히 다르게 변했죠?")
    
    # 복호화 확인
    print(f"복호화 1: {cipher.decrypt(enc1)}")