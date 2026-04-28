# ============================================================
#  Hackeadora — Dockerfile
#  Imagen base: Ubuntu 24.04
#  Autores: Claude (Anthropic) & Antonio Fernandes
# ============================================================
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV GO_VERSION=1.22.4
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin:/root/.local/bin

# ── Sistema base ──────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    git curl wget unzip tar jq sqlite3 \
    python3 python3-pip pipx \
    whatweb nmap \
    libpcap-dev build-essential \
    ca-certificates \
    masscan \
    && rm -rf /var/lib/apt/lists/*

# ── CMS tools ────────────────────────────────────────────────
RUN gem install wpscan 2>/dev/null || true &&     pip3 install --break-system-packages droopescan 2>/dev/null || true &&     git clone -q https://github.com/OWASP/joomscan.git /root/tools/joomscan 2>/dev/null || true &&     git clone -q https://github.com/0ang3el/aem-hacker.git /root/tools/aem-hacker 2>/dev/null &&     pip3 install --break-system-packages -r /root/tools/aem-hacker/requirements.txt 2>/dev/null || true &&     git clone -q https://github.com/fullhunt/log4j-scan.git /root/tools/log4j-scan 2>/dev/null &&     pip3 install --break-system-packages -r /root/tools/log4j-scan/requirements.txt 2>/dev/null || true

# ── Bloque A tools ───────────────────────────────────────────
RUN go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest 2>/dev/null || true && \
    go install github.com/trufflesecurity/trufflehog/v3@latest 2>/dev/null || true && \
    go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest 2>/dev/null || true

RUN pip3 install --break-system-packages paramspider arjun 2>/dev/null || true && \
    git clone -q https://github.com/initstring/cloud_enum.git /opt/cloud_enum 2>/dev/null && \
    pip3 install --break-system-packages -r /opt/cloud_enum/requirements.txt 2>/dev/null || true && \
    ln -sf /opt/cloud_enum/cloud_enum.py /usr/local/bin/cloud_enum 2>/dev/null || true

# ── Go ────────────────────────────────────────────────────────
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') && \
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz

# ── Herramientas Go ───────────────────────────────────────────
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/PentestPad/subzy@latest && \
    go install github.com/haccer/subjack@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/tomnomnom/anew@latest && \
    go install github.com/tomnomnom/unfurl@latest && \
    go install github.com/tomnomnom/qsreplace@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/hakluke/hakrawler@latest && \
    go install github.com/sensepost/gowitness@latest && \
    go install github.com/rverton/webanalyze/cmd/webanalyze@latest && \
    go install github.com/tomnomnom/assetfinder@latest

# ── Nuclei templates ──────────────────────────────────────────
RUN nuclei -update-templates -silent || true

# ── Python tools ──────────────────────────────────────────────
RUN pip3 install --break-system-packages \
    bbot \
    cryptography \
    boto3 \
    fastapi \
    uvicorn \
    requests \
    ghauri \
    dalfox 2>/dev/null || \
    pip3 install \
    bbot fastapi uvicorn requests 2>/dev/null || true

# ── Smuggler ─────────────────────────────────────────────────
RUN git clone -q https://github.com/defparam/smuggler.git /root/tools/smuggler 2>/dev/null || true

# ── SecretFinder ──────────────────────────────────────────────
RUN git clone -q https://github.com/m4ll0k/SecretFinder.git /root/tools/SecretFinder && \
    pip3 install --break-system-packages -r /root/tools/SecretFinder/requirements.txt || true

# ── Ghauri (SQLi) ─────────────────────────────────────────────
RUN git clone -q https://github.com/r0oth3x49/ghauri.git /root/tools/ghauri && \
    pip3 install --break-system-packages -r /root/tools/ghauri/requirements.txt && \
    ln -sf /root/tools/ghauri/ghauri.py /root/.local/bin/ghauri || true

# ── Dalfox (XSS) ─────────────────────────────────────────────
RUN go install github.com/hahwul/dalfox/v2@latest || true

# ── App ───────────────────────────────────────────────────────
WORKDIR /app
COPY . .
RUN chmod +x recon.sh install.sh modules/*.sh web/start.sh core/*.sh 2>/dev/null || true

# Directorios de datos (se montarán como volúmenes)
RUN mkdir -p /app/data /app/output

EXPOSE 8080

CMD ["python3", "-m", "uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8080"]
