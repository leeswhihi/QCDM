import hashlib
import hmac
import secrets
import os
import struct
import zlib
import argparse
import sys
from getpass import getpass

# --- [Core Engine] ---
class QCDM_Masterpiece:
    def __init__(self, key):
        self._key = key.encode()
        self.CHUNK_SIZE = 64 * 1024 # 64KB

    def _derive_key(self, salt):
        return hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)

    def _get_chunk_keystream(self, main_seed_bytes, chunk_index, length):
        index_bytes = chunk_index.to_bytes(8, 'big')
        chunk_seed = hmac.new(main_seed_bytes, index_bytes, hashlib.sha256).digest()
        return hashlib.shake_256(chunk_seed).digest(length)

    def process_file(self, mode, input_path, output_path):
        if mode == 'encrypt':
            print(f"🔒 암호화 시작: {input_path}")
            salt = secrets.token_bytes(16)
            derived_key = self._derive_key(salt)
            main_seed = hashlib.sha256(derived_key).digest()
            hmac_obj = hmac.new(derived_key, salt, hashlib.sha256)
            compressor = zlib.compressobj(level=6)
            
            # [수정된 부분] 압축 데이터를 모아둘 버퍼
            encrypt_buffer = bytearray()
            
            with open(output_path, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(b'\x00' * 32)
                
                chunk_idx = 0
                
                # 내부 함수: 버퍼에 있는 데이터를 64KB씩 잘라서 암호화 및 쓰기
                def flush_buffer(force=False):
                    nonlocal chunk_idx, encrypt_buffer
                    while len(encrypt_buffer) >= self.CHUNK_SIZE or (force and len(encrypt_buffer) > 0):
                        # 64KB 또는 남은 데이터만큼 자르기
                        slice_len = min(len(encrypt_buffer), self.CHUNK_SIZE)
                        chunk_data = encrypt_buffer[:slice_len]
                        del encrypt_buffer[:slice_len] # 버퍼에서 제거
                        
                        # 암호화
                        ks = self._get_chunk_keystream(main_seed, chunk_idx, len(chunk_data))
                        enc = bytes(a ^ b for a, b in zip(chunk_data, ks))
                        
                        f_out.write(enc)
                        hmac_obj.update(enc)
                        chunk_idx += 1

                with open(input_path, 'rb') as f_in:
                    while True:
                        raw = f_in.read(self.CHUNK_SIZE)
                        if not raw: break
                        
                        # 1. 압축 후 버퍼에 추가
                        compressed = compressor.compress(raw)
                        encrypt_buffer.extend(compressed)
                        
                        # 2. 버퍼가 64KB 넘으면 파일에 쓰기
                        flush_buffer(force=False)
                    
                    # 잔여 데이터 처리
                    encrypt_buffer.extend(compressor.flush())
                    flush_buffer(force=True) # 남은거 싹 다 쓰기
                
                f_out.seek(16)
                f_out.write(hmac_obj.digest())
                
        elif mode == 'decrypt':
            print(f"🔓 복호화 시작: {input_path}")
            with open(input_path, 'rb') as f_in:
                salt = f_in.read(16)
                expected_sig = f_in.read(32)
                
                derived_key = self._derive_key(salt)
                main_seed = hashlib.sha256(derived_key).digest()
                hmac_verify = hmac.new(derived_key, salt, hashlib.sha256)
                
                # 1. 무결성 검증
                body_start = f_in.tell()
                while True:
                    chunk = f_in.read(self.CHUNK_SIZE)
                    if not chunk: break
                    hmac_verify.update(chunk)
                
                if not hmac.compare_digest(hmac_verify.digest(), expected_sig):
                    print("❌ [치명적 오류] 파일이 변조되었거나 비밀번호가 틀렸습니다.")
                    return

                # 2. 복호화 및 압축 해제
                f_in.seek(body_start)
                decompressor = zlib.decompressobj()
                chunk_idx = 0
                
                with open(output_path, 'wb') as f_out:
                    while True:
                        # 암호화할 때 정확히 CHUNK_SIZE만큼 잘라서 썼으므로,
                        # 읽을 때도 정확히 CHUNK_SIZE만큼 읽으면 싱크가 맞음.
                        enc_chunk = f_in.read(self.CHUNK_SIZE)
                        if not enc_chunk: break
                        
                        ks = self._get_chunk_keystream(main_seed, chunk_idx, len(enc_chunk))
                        dec_chunk = bytes(a ^ b for a, b in zip(enc_chunk, ks))
                        
                        plain = decompressor.decompress(dec_chunk)
                        if plain: f_out.write(plain)
                        
                        chunk_idx += 1
                    
                    f_out.write(decompressor.flush())
        
        print(f"✅ 작업 완료: {output_path}")

# --- [User Interface] ---
def main():
    parser = argparse.ArgumentParser(description="QCDM v8.1 - Fixed & Stable")
    parser.add_argument("mode", choices=["enc", "dec"], help="enc: 암호화, dec: 복호화")
    parser.add_argument("input_file", help="대상 파일 경로")
    parser.add_argument("-o", "--output", help="저장할 파일 경로")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print("❌ 파일을 찾을 수 없습니다.")
        return

    if not args.output:
        if args.mode == 'enc':
            args.output = args.input_file + ".qcdm"
        else:
            args.output = args.input_file.replace(".qcdm", "") + ".restored"

    password = getpass("🔑 비밀번호를 입력하세요: ")
    if args.mode == 'enc':
        check_pw = getpass("🔑 확인을 위해 다시 입력하세요: ")
        if password != check_pw:
            print("❌ 비밀번호가 일치하지 않습니다.")
            return

    engine = QCDM_Masterpiece(password)
    try:
        if args.mode == 'enc':
            engine.process_file('encrypt', args.input_file, args.output)
        else:
            engine.process_file('decrypt', args.input_file, args.output)
    except Exception as e:
        print(f"⚠️ 오류 발생: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()