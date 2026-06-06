#!/bin/bash

set -e

echo "[+] Atualizando repositórios..."
sudo apt update

echo "[+] Instalando dependências eBPF/BCC..."
sudo apt install -y \
    bpfcc-tools \
    python3-bpfcc \
    linux-headers-$(uname -r) \
    clang \
    llvm

echo "[+] Instalação concluída!"