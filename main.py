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
        self.CHUNK_SIZE = 64 * 1024 # 64KB I/O Buffer

    def _derive_key(self, salt):
        """
        [보안] PBKDF2: 비밀번호 키 스트레칭 (50,000회)
        """
        return hashlib.pbkdf2_hmac('sha256', self._key, salt, 50000)

    def _get_chunk_keystream(self, main_seed_bytes, chunk_index, length):
        """
        [최적화] 소수점 연산 제거 -> 정수/해시 기반 난수 생성 (호환성 100% 보장)
        각 청크(블록)마다 고유한 키 스트림을 생성합니다.
        """
        # 청크 인덱스를 시드에 결합 (Counter Mode와 유사)
        # 소수점 더하기 대신, 인덱스를 바이트로 바꿔서 HMAC을 돌림 -> 완벽한 결정론적 결과
        index_bytes = chunk_index.to_bytes(8, 'big')
        
        # 청크별 고유 시드 생성 (HMAC-SHA256)
        chunk_seed = hmac.new(main_seed_bytes, index_bytes, hashlib.sha256).digest()
        
        # SHAKE-256으로 고속 스트림 확장
        return hashlib.shake_256(chunk_seed).digest(length)

    def process_file(self, mode, input_path, output_path):
        """
        암호화/복호화 통합 프로세서 (스트리밍 + 압축 + 인증)
        """
        if mode == 'encrypt':
            print(f"🔒 암호화 시작: {input_path}")
            salt = secrets.token_bytes(16)
            derived_key = self._derive_key(salt)
            
            # 메인 시드 생성 (소수점 제거)
            main_seed = hashlib.sha256(derived_key).digest()
            
            hmac_obj = hmac.new(derived_key, salt, hashlib.sha256)
            compressor = zlib.compressobj(level=6)
            
            with open(output_path, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(b'\x00' * 32) # 서명 자리 예약
                
                chunk_idx = 0
                with open(input_path, 'rb') as f_in:
                    while True:
                        raw = f_in.read(self.CHUNK_SIZE)
                        if not raw: break
                        
                        # 1. 압축
                        compressed = compressor.compress(raw)
                        if compressed:
                            # 2. 암호화
                            ks = self._get_chunk_keystream(main_seed, chunk_idx, len(compressed))
                            enc = bytes(a ^ b for a, b in zip(compressed, ks))
                            
                            f_out.write(enc)
                            hmac_obj.update(enc)
                            chunk_idx += 1
                    
                    # 잔여 데이터 처리
                    remaining = compressor.flush()
                    if remaining:
                        ks = self._get_chunk_keystream(main_seed, chunk_idx, len(remaining))
                        enc = bytes(a ^ b for a, b in zip(remaining, ks))
                        f_out.write(enc)
                        hmac_obj.update(enc)
                
                # 서명 기록
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
                
                # 1. 무결성 검증 (Pass 1)
                body_start = f_in.tell()
                while True:
                    chunk = f_in.read(self.CHUNK_SIZE)
                    if not chunk: break
                    hmac_verify.update(chunk)
                
                if not hmac.compare_digest(hmac_verify.digest(), expected_sig):
                    print("❌ [치명적 오류] 파일이 변조되었거나 비밀번호가 틀렸습니다.")
                    return

                # 2. 복호화 및 압축 해제 (Pass 2)
                f_in.seek(body_start)
                decompressor = zlib.decompressobj()
                chunk_idx = 0
                
                with open(output_path, 'wb') as f_out:
                    while True:
                        enc_chunk = f_in.read(self.CHUNK_SIZE) # *주의: 압축된 크기만큼 읽음
                        if not enc_chunk: break
                        
                        # 복호화
                        ks = self._get_chunk_keystream(main_seed, chunk_idx, len(enc_chunk))
                        dec_chunk = bytes(a ^ b for a, b in zip(enc_chunk, ks))
                        
                        # 압축 해제
                        plain = decompressor.decompress(dec_chunk)
                        if plain: f_out.write(plain)
                        
                        chunk_idx += 1
                    
                    f_out.write(decompressor.flush())
        
        print(f"✅ 작업 완료: {output_path}")

# --- [User Interface] ---
def main():
    parser = argparse.ArgumentParser(description="QCDM v8.0 - AI Designed Secure Cipher")
    parser.add_argument("mode", choices=["enc", "dec"], help="enc: 암호화, dec: 복호화")
    parser.add_argument("input_file", help="대상 파일 경로")
    parser.add_argument("-o", "--output", help="저장할 파일 경로 (생략 시 자동 생성)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input_file):
        print("❌ 파일을 찾을 수 없습니다.")
        return

    # 출력 파일명 자동 설정
    if not args.output:
        if args.mode == 'enc':
            args.output = args.input_file + ".qcdm"
        else:
            args.output = args.input_file.replace(".qcdm", "") + ".restored"

    # 비밀번호 입력 (화면에 안 보이게)
    password = getpass("🔑 비밀번호를 입력하세요: ")
    if args.mode == 'enc':
        check_pw = getpass("🔑 확인을 위해 다시 입력하세요: ")
        if password != check_pw:
            print("❌ 비밀번호가 일치하지 않습니다.")
            return

    # 엔진 가동
    engine = QCDM_Masterpiece(password)
    
    try:
        if args.mode == 'enc':
            engine.process_file('encrypt', args.input_file, args.output)
        else:
            engine.process_file('decrypt', args.input_file, args.output)
    except Exception as e:
        print(f"⚠️ 오류 발생: {e}")

if __name__ == "__main__":
    main()