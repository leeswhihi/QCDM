import hashlib
import base64

class QCDM_Cipher:
    def __init__(self, key):
        # 1. 키를 해싱하여 고정된 길이의 시드 생성
        self.key_hash = hashlib.sha256(key.encode()).digest()
        self.seed = int.from_bytes(self.key_hash, 'big')

    def _logistic_map(self, x, n_steps=10):
        # 카오스 이론: 로지스틱 맵 함수
        r = 3.9999  # 카오스 영역 상수
        for _ in range(n_steps):
            x = r * x * (1 - x)
        return x

    def _generate_dynamic_key(self, index, length):
        # 인덱스에 따라 변하는 동적 키 스트림 생성
        # 초기 시드에 인덱스를 더해 매번 다른 초기값 생성
        initial_val = (self.seed + index) % 100000 / 100000.0
        if initial_val == 0: initial_val = 0.123456
        
        chaos_val = self._logistic_map(initial_val)
        
        # 0~255 사이의 정수로 변환
        return int(chaos_val * 1000000) % 256

    def encrypt(self, plaintext):
        encrypted_bytes = bytearray()
        
        # 문자열을 바이트로 변환
        text_bytes = plaintext.encode('utf-8')
        
        for i, byte in enumerate(text_bytes):
            # 1. 동적 키 생성 (카오스)
            dynamic_k = self._generate_dynamic_key(i, len(text_bytes))
            
            # 2. XOR 연산 (1차 난독화)
            cipher_byte = byte ^ dynamic_k
            
            # 3. 비트 회전 (2차 난독화 - 순환 이동)
            # 동적 키의 하위 3비트만큼 왼쪽으로 회전
            shift = dynamic_k % 8
            cipher_byte = ((cipher_byte << shift) | (cipher_byte >> (8 - shift))) & 0xFF
            
            # 4. 피드백 체이닝 (이전 암호문이 현재 암호화에 영향)
            if i > 0:
                cipher_byte = cipher_byte ^ encrypted_bytes[i-1]
                
            encrypted_bytes.append(cipher_byte)
            
        # Base64로 인코딩하여 출력
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt(self, ciphertext):
        decoded_bytes = base64.b64decode(ciphertext)
        decrypted_bytes = bytearray()
        
        for i in range(len(decoded_bytes)):
            # 암호화의 역순으로 진행
            cipher_byte = decoded_bytes[i]
            
            # 4. 피드백 체이닝 해제
            temp_byte = cipher_byte
            if i > 0:
                temp_byte = temp_byte ^ decoded_bytes[i-1]
            
            # 1. 동적 키 재생성 (대칭키 방식이므로 동일)
            dynamic_k = self._generate_dynamic_key(i, len(decoded_bytes))
            
            # 3. 비트 회전 반대로 (오른쪽 회전)
            shift = dynamic_k % 8
            original_byte = ((temp_byte >> shift) | (temp_byte << (8 - shift))) & 0xFF
            
            # 2. XOR 연산 복구
            original_byte = original_byte ^ dynamic_k
            
            decrypted_bytes.append(original_byte)
            
        return decrypted_bytes.decode('utf-8')

# --- 사용 예시 ---
if __name__ == "__main__":
    key = "Gemini_Secret_Key_2026"
    message = "Hello! This is a unique chaotic cipher."

    cipher = QCDM_Cipher(key)
    
    encrypted = cipher.encrypt(message)
    print(f"🔒 암호문: {encrypted}")
    
    decrypted = cipher.decrypt(encrypted)
    print(f"🔓 복호문: {decrypted}")