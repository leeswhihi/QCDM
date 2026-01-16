import hashlib
import hmac
import secrets
import os
import struct
import zlib
import argparse
import sys
from getpass import getpass

# 프로그레스 바 라이브러리 임포트 (없으면 설치 안내 메시지 출력)
try:
    from tqdm import tqdm
except ImportError:
    print("❌ 'tqdm' 라이브러리가 설치되지 않았습니다.")
    print("   pip install tqdm 명령어로 설치해주세요.")
    sys.exit(1)

class QCDM_Smart:
    def __init__(self, key):
        self._key = key.encode()
        self.CHUNK_SIZE = 64 * 1024 # 64KB

    def _derive_key(self, salt):
        return hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)

    def _get_chunk_keystream(self, main_seed_bytes, chunk_index, length):
        index_bytes = chunk_index.to_bytes(8, 'big')
        chunk_seed = hmac.new(main_seed_bytes, index_bytes, hashlib.sha256).digest()
        return hashlib.shake_256(chunk_seed).digest(length)

    def process_file(self, mode, input_path, output_path=None):
        # 파일 전체 크기 확인 (프로그레스 바용)
        file_total_size = os.path.getsize(input_path)

        if mode == 'encrypt':
            # 1. 원본 확장자 추출
            file_ext = os.path.splitext(input_path)[1]
            ext_bytes = file_ext.encode('utf-8')
            ext_len = len(ext_bytes)
            
            if not output_path:
                base_name = os.path.splitext(os.path.basename(input_path))[0]
                output_path = base_name + ".qcdm"

            print(f"🔒 암호화 시작: {input_path}")
            
            salt = secrets.token_bytes(16)
            derived_key = self._derive_key(salt)
            main_seed = hashlib.sha256(derived_key).digest()
            hmac_obj = hmac.new(derived_key, salt, hashlib.sha256)
            compressor = zlib.compressobj(level=6)
            
            encrypt_buffer = bytearray()
            
            with open(output_path, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(b'\x00' * 32)
                f_out.write(struct.pack('B', ext_len))
                f_out.write(ext_bytes)
                
                hmac_obj.update(struct.pack('B', ext_len))
                hmac_obj.update(ext_bytes)
                
                chunk_idx = 0
                
                def flush_buffer(force=False):
                    nonlocal chunk_idx, encrypt_buffer
                    while len(encrypt_buffer) >= self.CHUNK_SIZE or (force and len(encrypt_buffer) > 0):
                        slice_len = min(len(encrypt_buffer), self.CHUNK_SIZE)
                        chunk_data = encrypt_buffer[:slice_len]
                        del encrypt_buffer[:slice_len]
                        
                        ks = self._get_chunk_keystream(main_seed, chunk_idx, len(chunk_data))
                        enc = bytes(a ^ b for a, b in zip(chunk_data, ks))
                        
                        f_out.write(enc)
                        hmac_obj.update(enc)
                        chunk_idx += 1

                # [수정] tqdm을 사용하여 암호화 진행률 표시
                with open(input_path, 'rb') as f_in, tqdm(total=file_total_size, unit='B', unit_scale=True, desc="Encrypting", ncols=80) as pbar:
                    while True:
                        raw = f_in.read(self.CHUNK_SIZE)
                        if not raw: break
                        
                        # 읽은 크기만큼 진행률 업데이트
                        pbar.update(len(raw))
                        
                        encrypt_buffer.extend(compressor.compress(raw))
                        flush_buffer(force=False)
                    
                    encrypt_buffer.extend(compressor.flush())
                    flush_buffer(force=True)
                
                f_out.seek(16)
                f_out.write(hmac_obj.digest())
                
            print(f"✅ 암호화 완료: {output_path}")
                
        elif mode == 'decrypt':
            print(f"🔓 복호화 준비 중...")
            with open(input_path, 'rb') as f_in:
                salt = f_in.read(16)
                expected_sig = f_in.read(32)
                
                derived_key = self._derive_key(salt)
                main_seed = hashlib.sha256(derived_key).digest()
                hmac_verify = hmac.new(derived_key, salt, hashlib.sha256)
                
                ext_len = struct.unpack('B', f_in.read(1))[0]
                ext_bytes = f_in.read(ext_len)
                original_ext = ext_bytes.decode('utf-8')
                
                hmac_verify.update(struct.pack('B', ext_len))
                hmac_verify.update(ext_bytes)
                
                if not output_path:
                    base_name = os.path.splitext(os.path.basename(input_path))[0]
                    output_path = base_name + original_ext
                    if not original_ext:
                         output_path += ".restored"

                body_start = f_in.tell()
                
                # 검증 단계 (빠르게 읽기)
                print("   ↳ 무결성 검증 중...", end='\r')
                while True:
                    chunk = f_in.read(self.CHUNK_SIZE)
                    if not chunk: break
                    hmac_verify.update(chunk)
                
                if not hmac.compare_digest(hmac_verify.digest(), expected_sig):
                    print("\n❌ 파일이 변조되었거나 비밀번호가 틀렸습니다.")
                    return
                print("   ↳ 무결성 검증 완료.   ")

                # 복호화 단계 시작
                f_in.seek(body_start)
                decompressor = zlib.decompressobj()
                chunk_idx = 0
                
                # 복호화 할 실제 데이터 크기 계산
                enc_body_size = file_total_size - body_start

                # [수정] tqdm을 사용하여 복호화 진행률 표시
                with open(output_path, 'wb') as f_out, tqdm(total=enc_body_size, unit='B', unit_scale=True, desc="Decrypting", ncols=80) as pbar:
                    while True:
                        enc_chunk = f_in.read(self.CHUNK_SIZE)
                        if not enc_chunk: break
                        
                        pbar.update(len(enc_chunk)) # 진행률 업데이트
                        
                        ks = self._get_chunk_keystream(main_seed, chunk_idx, len(enc_chunk))
                        dec_chunk = bytes(a ^ b for a, b in zip(enc_chunk, ks))
                        
                        plain = decompressor.decompress(dec_chunk)
                        if plain: f_out.write(plain)
                        chunk_idx += 1
                    
                    f_out.write(decompressor.flush())
            
            print(f"✅ 복호화 완료! ({output_path})")

def main():
    parser = argparse.ArgumentParser(description="QCDM v9.2 - Smart Progress")
    parser.add_argument("mode", choices=["enc", "dec"], help="enc: 암호화, dec: 복호화")
    parser.add_argument("input_file", help="대상 파일 경로")
    parser.add_argument("-o", "--output", help="저장할 파일 경로 (생략 시 자동 복구)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print("❌ 파일을 찾을 수 없습니다.")
        return

    password = getpass("비밀번호를 입력하세요: ")
    if args.mode == 'enc':
        check_pw = getpass("확인을 위해 다시 입력하세요: ")
        if password != check_pw:
            print("❌ 비밀번호가 일치하지 않습니다.")
            return

    engine = QCDM_Smart(password)
    try:
        engine.process_file(args.mode == 'enc' and 'encrypt' or 'decrypt', 
                           args.input_file, 
                           args.output)
    except Exception as e:
        print(f"\n⚠️ 오류 발생: {e}")
        # import traceback
        # traceback.print_exc()

if __name__ == "__main__":
    main()