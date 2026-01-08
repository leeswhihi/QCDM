import hashlib
import hmac
import secrets
import os
import struct
import zlib  # [New] 데이터 압축 라이브러리

class QCDM_Singularity:
    def __init__(self, key):
        self._key = key.encode()
        self.CHUNK_SIZE = 64 * 1024 # 64KB

    def _get_chunk_keystream(self, seed_val, length):
        # 카오스 + SHAKE256 하이브리드 키 스트림
        r = 3.9999
        chaos = r * seed_val * (1 - seed_val)
        seed_bytes = struct.pack('d', chaos)
        return hashlib.shake_256(seed_bytes).digest(length)

    def encrypt_file(self, input_path, output_path):
        salt = secrets.token_bytes(16)
        derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)
        
        seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
        if seed_val == 0: seed_val = 0.123456789

        hmac_obj = hmac.new(derived_key, salt, hashlib.sha256)
        
        # [New] 압축 객체 생성
        compressor = zlib.compressobj(level=6) 

        file_size_original = os.path.getsize(input_path)
        print(f"🔄 작업 시작: {input_path} ({file_size_original:,} bytes)")

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(b'\x00' * 32) # 서명 공간 확보
            
            chunk_index = 0
            
            def process_and_write(raw_data):
                nonlocal chunk_index, seed_val
                
                # 데이터가 비어있으면 패스
                if not raw_data: return

                # 시드 변형
                chunk_seed = seed_val + (chunk_index * 0.0000001)
                while chunk_seed > 1: chunk_seed -= 1
                
                # 키 스트림 생성 및 암호화
                keystream = self._get_chunk_keystream(chunk_seed, len(raw_data))
                
                int_data = int.from_bytes(raw_data, 'big')
                int_key = int.from_bytes(keystream, 'big')
                cipher_chunk = (int_data ^ int_key).to_bytes(len(raw_data), 'big')
                
                f_out.write(cipher_chunk)
                hmac_obj.update(cipher_chunk)
                chunk_index += 1

            while True:
                chunk = f_in.read(self.CHUNK_SIZE)
                if not chunk: break
                
                # 1. 읽은 데이터를 압축
                compressed_chunk = compressor.compress(chunk)
                
                # 2. 압축된 데이터가 나오면 암호화해서 저장
                if compressed_chunk:
                    process_and_write(compressed_chunk)
            
            # 3. 남은 압축 데이터 처리 (Flush)
            remaining = compressor.flush()
            if remaining:
                process_and_write(remaining)

            # 서명 기록
            signature = hmac_obj.digest()
            f_out.seek(16)
            f_out.write(signature)
            
        final_size = os.path.getsize(output_path)
        ratio = (1 - final_size/file_size_original) * 100
        print(f"✅ 완료! 크기: {final_size:,} bytes (압축률: {ratio:.1f}%)")

    def decrypt_file(self, input_path, output_path):
        with open(input_path, 'rb') as f_in:
            salt = f_in.read(16)
            expected_sig = f_in.read(32)
            
            derived_key = hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)
            hmac_verify = hmac.new(derived_key, salt, hashlib.sha256)
            
            body_start = f_in.tell()
            
            # 무결성 검증
            print("🔍 파일 무결성 검증 중...")
            while True:
                chunk = f_in.read(self.CHUNK_SIZE)
                if not chunk: break
                hmac_verify.update(chunk)
                
            if not hmac.compare_digest(hmac_verify.digest(), expected_sig):
                print("🚨 오류: 파일이 손상되었습니다.")
                return

            # 복호화 및 압축 해제 시작
            f_in.seek(body_start)
            seed_val = int.from_bytes(derived_key[:4], 'big') / (2**32)
            if seed_val == 0: seed_val = 0.123456789
            
            # [New] 압축 해제 객체
            decompressor = zlib.decompressobj()
            
            chunk_index = 0
            
            with open(output_path, 'wb') as f_out:
                while True:
                    cipher_chunk = f_in.read(self.CHUNK_SIZE)
                    if not cipher_chunk: break
                    
                    chunk_seed = seed_val + (chunk_index * 0.0000001)
                    while chunk_seed > 1: chunk_seed -= 1
                    
                    keystream = self._get_chunk_keystream(chunk_seed, len(cipher_chunk))
                    
                    int_cipher = int.from_bytes(cipher_chunk, 'big')
                    int_key = int.from_bytes(keystream, 'big')
                    compressed_data = (int_cipher ^ int_key).to_bytes(len(cipher_chunk), 'big')
                    
                    # 1. 복호화된 데이터를 압축 해제기에 넣음
                    decompressed_chunk = decompressor.decompress(compressed_data)
                    
                    # 2. 압축 해제된 원본 데이터 저장
                    if decompressed_chunk:
                        f_out.write(decompressed_chunk)
                    
                    chunk_index += 1
                
                # 남은 데이터 처리
                f_out.write(decompressor.flush())
                
        print("✅ 복호화 및 복원 완료!")

# --- 최종 테스트 ---
if __name__ == "__main__":
    # 테스트용 파일 생성 (반복되는 내용이 많아 압축 효과가 좋은 파일)
    sample_text = "이것은 최고의 암호화 알고리즘입니다. " * 100000
    with open("secret_doc.txt", "w", encoding='utf-8') as f:
        f.write(sample_text)
        
    cipher = QCDM_Singularity("My_Final_Password")
    
    # 암호화 (압축 효과 확인)
    cipher.encrypt_file("secret_doc.txt", "secret.qcdm")
    
    # 복호화
    cipher.decrypt_file("secret.qcdm", "recovered_doc.txt")
    
    # 정리
    os.remove("secret_doc.txt")
    os.remove("secret.qcdm")
    os.remove("recovered_doc.txt")