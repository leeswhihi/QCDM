import hashlib
import hmac
import secrets
import os
import struct

class QCDM_Omega:
    def __init__(self, key):
        self._key = key.encode()
        self.CHUNK_SIZE = 64 * 1024  # 64KB 단위로 처리 (I/O 속도 최적화)

    def _get_chunk_keystream(self, seed_val, length):
        """
        [최적화] 청크 단위 키 스트림 생성
        """
        r = 3.9999
        chaos = r * seed_val * (1 - seed_val)
        seed_bytes = struct.pack('d', chaos)
        return hashlib.shake_256(seed_bytes).digest(length)

    def encrypt_file(self, input_path, output_path):
        """
        [마지막 원리: 스트리밍]
        파일을 조금씩 읽어서 암호화하므로, 메모리가 터지지 않습니다.
        """
        salt = secrets.token_bytes(16)
        derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)
        
        # 카오스 시드 초기화
        seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
        if seed_val == 0: seed_val = 0.123456789

        # HMAC 계산을 위한 객체 (스트리밍 방식)
        hmac_obj = hmac.new(derived_key, salt, hashlib.sha256)

        file_size = os.path.getsize(input_path)
        
        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # 1. 헤더 쓰기 (Salt)
            f_out.write(salt)
            
            # 2. 서명을 위한 자리 비워두기 (나중에 덮어씀)
            f_out.write(b'\x00' * 32)
            
            processed = 0
            chunk_index = 0
            
            print(f"🔄 암호화 시작: {input_path} ({file_size/1024/1024:.2f} MB)")
            
            while True:
                chunk = f_in.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                
                # 청크마다 미세하게 변하는 시드값 (패턴 반복 방지)
                # 시드가 고정되면 모든 청크가 같은 키로 암호화되는 취약점 발생 -> 인덱스 섞음
                chunk_seed = seed_val + (chunk_index * 0.0000001)
                while chunk_seed > 1: chunk_seed -= 1
                
                keystream = self._get_chunk_keystream(chunk_seed, len(chunk))
                
                # 고속 XOR (청크 단위 Big Int 변환)
                int_chunk = int.from_bytes(chunk, 'big')
                int_key = int.from_bytes(keystream, 'big')
                int_cipher = int_chunk ^ int_key
                
                cipher_bytes = int_cipher.to_bytes(len(chunk), 'big')
                
                # 파일 쓰기
                f_out.write(cipher_bytes)
                
                # HMAC 업데이트 (메모리에 다 올리지 않고 누적 계산)
                hmac_obj.update(cipher_bytes)
                
                processed += len(chunk)
                chunk_index += 1
                
            # 3. 최종 서명 계산 및 헤더 업데이트
            signature = hmac_obj.digest()
            f_out.seek(16) # Salt 다음 위치로 이동
            f_out.write(signature) # 서명 기록
            
        print("✅ 암호화 완료!")

    def decrypt_file(self, input_path, output_path):
        with open(input_path, 'rb') as f_in:
            # 헤더 읽기
            salt = f_in.read(16)
            expected_sig = f_in.read(32)
            
            derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)
            
            # HMAC 검증을 위한 객체
            hmac_verify = hmac.new(derived_key, salt, hashlib.sha256)
            
            # 본문 시작 위치 기억
            body_start = f_in.tell()
            
            # 1. 무결성 검증 (먼저 파일을 끝까지 읽어서 서명 확인)
            # *보안상 복호화 전에 변조 여부 확인이 필수
            print("🔍 무결성 검증 중...")
            while True:
                chunk = f_in.read(self.CHUNK_SIZE)
                if not chunk: break
                hmac_verify.update(chunk)
                
            if not hmac.compare_digest(hmac_verify.digest(), expected_sig):
                print("🚨 경고: 파일이 변조되었습니다! 복호화를 중단합니다.")
                return

            # 2. 검증 완료 후 다시 처음으로 돌아가서 복호화 수행
            f_in.seek(body_start)
            seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
            if seed_val == 0: seed_val = 0.123456789
            
            chunk_index = 0
            with open(output_path, 'wb') as f_out:
                while True:
                    chunk = f_in.read(self.CHUNK_SIZE)
                    if not chunk: break
                    
                    chunk_seed = seed_val + (chunk_index * 0.0000001)
                    while chunk_seed > 1: chunk_seed -= 1
                    
                    keystream = self._get_chunk_keystream(chunk_seed, len(chunk))
                    
                    int_chunk = int.from_bytes(chunk, 'big')
                    int_key = int.from_bytes(keystream, 'big')
                    int_plain = int_chunk ^ int_key
                    
                    plain_bytes = int_plain.to_bytes(len(chunk), 'big')
                    f_out.write(plain_bytes)
                    
                    chunk_index += 1
                    
        print("✅ 복호화 완료!")

# --- 사용 예시 ---
if __name__ == "__main__":
    # 테스트를 위한 더미 파일 생성 (10MB)
    dummy_file = "test_video.mp4"
    with open(dummy_file, "wb") as f:
        f.write(os.urandom(10 * 1024 * 1024))
        
    key = "Final_Key_Omega"
    cipher = QCDM_Omega(key)
    
    # 파일 암호화
    cipher.encrypt_file(dummy_file, "encrypted.qcdm")
    
    # 파일 복호화
    cipher.decrypt_file("encrypted.qcdm", "restored_video.mp4")
    
    # 정리
    os.remove(dummy_file)
    os.remove("encrypted.qcdm")
    os.remove("restored_video.mp4")