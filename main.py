import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

app = FastAPI(
    title="API de Criptografia de Envelope Digital",
    description="Segurança da Informação"
)

armazenamento_chaves: Dict[str, Any] = {}

class RespostaGeracaoChave(BaseModel):
    chave_publica_pem: str
    chave_privada_pem: str

class RequisicaoCriptografia(BaseModel):
    texto_simples: str
    chave_publica_pem: str

class RespostaCriptografia(BaseModel):
    dados_criptografados: str
    chave_aes_criptografada: str

class RequisicaoDescriptografia(BaseModel):
    dados_criptografados: str
    chave_aes_criptografada: str
    chave_privada_pem: str

class RespostaDescriptografia(BaseModel):
    texto_simples: str

def gerar_par_chaves_rsa(tamanho_chave: int = 3072):
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamanho_chave,
        backend=default_backend()
    )
    chave_publica = chave_privada.public_key()
    return chave_privada, chave_publica

def serializar_chave_privada(chave_privada):
    bytes_privados = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return bytes_privados.decode('utf-8')

def serializar_chave_publica(chave_publica):
    bytes_publicos = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return bytes_publicos.decode('utf-8')

def carregar_chave_privada(chave_privada_pem: str):
    try:
        return serialization.load_pem_private_key(
            chave_privada_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao carregar a chave privada: {e}")

def carregar_chave_publica(chave_publica_pem: str):
    try:
        return serialization.load_pem_public_key(
            chave_publica_pem.encode('utf-8'),
            backend=default_backend()
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro ao carregar a chave pública: {e}")

def encEnvelopeDigital(dados_texto_simples: bytes, chave_publica_destinatario):
    chave_aes = os.urandom(32)
    
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(dados_texto_simples) + padder.finalize()
    
    cifrador = Cipher(algorithms.AES(chave_aes), modes.ECB(), backend=default_backend())
    criptografador = cifrador.encryptor()
    texto_cifrado_aes = criptografador.update(padded_data) + criptografador.finalize()
    
    preenchimento_rsa = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    chave_aes_criptografada = chave_publica_destinatario.encrypt(chave_aes, preenchimento_rsa)

    return texto_cifrado_aes, chave_aes_criptografada

def decEnvelopeDigital(texto_cifrado_aes: bytes, chave_aes_criptografada: bytes, chave_privada_destinatario):
    preenchimento_rsa = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    chave_aes_descriptografada = chave_privada_destinatario.decrypt(chave_aes_criptografada, preenchimento_rsa)
    
    cifrador = Cipher(algorithms.AES(chave_aes_descriptografada), modes.ECB(), backend=default_backend())
    descriptografador = cifrador.decryptor()
    dados_descriptografados = descriptografador.update(texto_cifrado_aes) + descriptografador.finalize()
    
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    dados_texto_simples = unpadder.update(dados_descriptografados) + unpadder.finalize()

    return dados_texto_simples

@app.post("/gerar_chaves", response_model=RespostaGeracaoChave)
async def gerar_chaves():
    chave_privada, chave_publica = gerar_par_chaves_rsa()
    chave_privada_pem = serializar_chave_privada(chave_privada)
    chave_publica_pem = serializar_chave_publica(chave_publica)
    
    armazenamento_chaves["chave_privada"] = chave_privada
    armazenamento_chaves["chave_publica"] = chave_publica

    return {
        "chave_publica_pem": chave_publica_pem,
        "chave_privada_pem": chave_privada_pem
    }

@app.post("/criptografar", response_model=RespostaCriptografia)
async def criptografar_dados(requisicao: RequisicaoCriptografia):
    try:
        dados_texto_simples = requisicao.texto_simples.encode('utf-8')
        chave_publica = carregar_chave_publica(requisicao.chave_publica_pem)

        dados_criptografados, chave_aes_criptografada = encEnvelopeDigital(
            dados_texto_simples,
            chave_publica
        )
        
        return {
            "dados_criptografados": dados_criptografados.hex(),
            "chave_aes_criptografada": chave_aes_criptografada.hex()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro durante a criptografia: {e}")

@app.post("/descriptografar", response_model=RespostaDescriptografia)
async def descriptografar_dados(requisicao: RequisicaoDescriptografia):
    try:
        dados_criptografados = bytes.fromhex(requisicao.dados_criptografados)
        chave_aes_criptografada = bytes.fromhex(requisicao.chave_aes_criptografada)
        
        chave_privada = carregar_chave_privada(requisicao.chave_privada_pem)
        
        dados_descriptografados = decEnvelopeDigital(
            dados_criptografados,
            chave_aes_criptografada,
            chave_privada
        )
        
        return {"texto_simples": dados_descriptografados.decode('utf-8')}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro durante a decriptografia: {e}")
