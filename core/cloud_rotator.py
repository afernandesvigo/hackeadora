#!/usr/bin/env python3
"""
core/cloud_rotator.py — Rotación de IPs via instancias spot AWS
Levanta instancias t3.small spot, ejecuta comandos desde ellas
y las destruye al terminar. IP diferente en cada rotación.

Uso desde módulos bash:
  python3 core/cloud_rotator.py --exec "nuclei -u target.com" --collect /tmp/out.json
  python3 core/cloud_rotator.py --status
  python3 core/cloud_rotator.py --cleanup
"""

import os
import sys
import json
import time
import argparse
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("[!] boto3 no instalado: pip3 install boto3")
    sys.exit(1)

# ── Config ────────────────────────────────────────────────────
AWS_REGION        = os.environ.get("AWS_REGION", "eu-west-1")
AWS_ACCESS_KEY    = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY    = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
ROTATION_INTERVAL = int(os.environ.get("ROTATION_INTERVAL", "500"))
INSTANCE_TYPE     = os.environ.get("AWS_INSTANCE_TYPE", "t3.small")
SPOT_MAX_PRICE    = os.environ.get("AWS_SPOT_MAX_PRICE", "0.02")  # $/hora máximo
S3_BUCKET         = os.environ.get("AWS_S3_BUCKET", "")          # para resultados
KEY_PAIR_NAME     = os.environ.get("AWS_KEY_PAIR", "hackeadora")
SECURITY_GROUP    = os.environ.get("AWS_SECURITY_GROUP", "")
AMI_ID            = os.environ.get("AWS_AMI_ID", "")             # AMI pre-built

BASE_DIR  = Path(__file__).parent.parent
STATE_FILE = BASE_DIR / "data" / "rotator_state.json"

# User data script que se ejecuta al arrancar la instancia
# Instala las herramientas de Hackeadora si no hay AMI pre-built
BOOTSTRAP_SCRIPT = """#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

# Instalar Go y herramientas básicas
apt-get update -qq
apt-get install -y curl wget git jq unzip python3 python3-pip libpcap-dev

# Go
wget -q https://go.dev/dl/go1.22.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc

# Herramientas esenciales
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Nuclei templates
/root/go/bin/nuclei -update-templates -silent

# Señal de que el bootstrap terminó
touch /tmp/hackeadora_ready
"""

# ── AWS client ────────────────────────────────────────────────
def get_ec2():
    return boto3.client(
        "ec2",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY or None,
        aws_secret_access_key=AWS_SECRET_KEY or None,
    )

def get_s3():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY or None,
        aws_secret_access_key=AWS_SECRET_KEY or None,
    )

# ── State management ──────────────────────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"instances": [], "request_count": 0, "total_cost": 0.0}

def save_state(state: dict):
    STATE_FILE.parent.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))

# ── Security group setup ──────────────────────────────────────
def ensure_security_group(ec2) -> str:
    """Crea o reutiliza el security group de Hackeadora."""
    global SECURITY_GROUP
    if SECURITY_GROUP:
        return SECURITY_GROUP

    try:
        # Buscar si ya existe
        sgs = ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": ["hackeadora-scanner"]}]
        )
        if sgs["SecurityGroups"]:
            SECURITY_GROUP = sgs["SecurityGroups"][0]["GroupId"]
            print(f"  Security group existente: {SECURITY_GROUP}")
            return SECURITY_GROUP

        # Crear nuevo
        sg = ec2.create_security_group(
            GroupName="hackeadora-scanner",
            Description="Hackeadora scanner instances — outbound only"
        )
        sg_id = sg["GroupId"]

        # Solo outbound (no inbound — las instancias no necesitan recibir conexiones)
        # El outbound por defecto ya permite todo
        print(f"  Security group creado: {sg_id}")
        SECURITY_GROUP = sg_id
        return sg_id

    except ClientError as e:
        print(f"  [!] Error con security group: {e}")
        return ""

# ── Key pair setup ────────────────────────────────────────────
def ensure_key_pair(ec2) -> Optional[str]:
    """Crea o verifica el key pair para SSH."""
    key_file = BASE_DIR / "data" / f"{KEY_PAIR_NAME}.pem"

    try:
        # Verificar si ya existe en AWS
        ec2.describe_key_pairs(KeyNames=[KEY_PAIR_NAME])
        if key_file.exists():
            return str(key_file)
        print(f"  [!] Key pair {KEY_PAIR_NAME} existe en AWS pero no localmente")
        print(f"      Elimínalo en AWS Console y vuelve a ejecutar")
        return None

    except ClientError:
        # No existe — crear
        print(f"  Creando key pair {KEY_PAIR_NAME}...")
        kp = ec2.create_key_pair(KeyName=KEY_PAIR_NAME)
        key_file.write_text(kp["KeyMaterial"])
        key_file.chmod(0o400)
        print(f"  Key pair guardado en: {key_file}")
        return str(key_file)

# ── AMI selection ─────────────────────────────────────────────
def get_ami(ec2) -> str:
    """Devuelve AMI ID: pre-built si existe, sino Ubuntu 22.04 LTS."""
    global AMI_ID
    if AMI_ID:
        return AMI_ID

    # Ubuntu 22.04 LTS en eu-west-1 (actualiza según región)
    UBUNTU_AMIS = {
        "eu-west-1":    "ami-0694d931cee176e7d",
        "us-east-1":    "ami-0261755bbcb8c4a84",
        "us-west-2":    "ami-0eb9fdcf0d07bd5ef",
        "ap-southeast-1": "ami-078c1149d8ad719a7",
        "eu-central-1": "ami-0faab6bdbac9486fb",
    }

    ami = UBUNTU_AMIS.get(AWS_REGION)
    if not ami:
        # Buscar dinámicamente
        images = ec2.describe_images(
            Owners=["099720109477"],  # Canonical
            Filters=[
                {"Name": "name", "Values": ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )
        images["Images"].sort(key=lambda x: x["CreationDate"], reverse=True)
        ami = images["Images"][0]["ImageId"] if images["Images"] else ""

    AMI_ID = ami
    return ami

# ── Lanzar instancia spot ─────────────────────────────────────
def launch_spot_instance(ec2, use_bootstrap: bool = True) -> Optional[dict]:
    """
    Lanza una instancia spot t3.small.
    Devuelve info de la instancia o None si falla.
    """
    print(f"\n  [→] Lanzando instancia spot {INSTANCE_TYPE} en {AWS_REGION}...")

    ami      = get_ami(ec2)
    sg_id    = ensure_security_group(ec2)
    key_file = ensure_key_pair(ec2)

    if not ami:
        print("  [!] No se encontró AMI válida")
        return None

    user_data = BOOTSTRAP_SCRIPT if use_bootstrap and not AMI_ID else "#!/bin/bash\ntouch /tmp/hackeadora_ready"

    try:
        response = ec2.run_instances(
            ImageId=ami,
            InstanceType=INSTANCE_TYPE,
            MinCount=1,
            MaxCount=1,
            KeyName=KEY_PAIR_NAME,
            SecurityGroupIds=[sg_id] if sg_id else [],
            UserData=user_data,
            # Spot instance request
            InstanceMarketOptions={
                "MarketType": "spot",
                "SpotOptions": {
                    "MaxPrice": SPOT_MAX_PRICE,
                    "SpotInstanceType": "one-time",
                }
            },
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": "hackeadora-scanner"},
                    {"Key": "Project", "Value": "hackeadora"},
                    {"Key": "AutoTerminate", "Value": "true"},
                ]
            }],
            # Sin almacenamiento persistente — ephemeral
            BlockDeviceMappings=[{
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "VolumeSize": 20,
                    "VolumeType": "gp3",
                    "DeleteOnTermination": True,
                }
            }],
        )

        instance = response["Instances"][0]
        instance_id = instance["InstanceId"]
        print(f"  Instancia lanzada: {instance_id}")

        # Esperar a que esté running
        print("  Esperando estado 'running'...")
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id])

        # Obtener IP pública
        info = ec2.describe_instances(InstanceIds=[instance_id])
        inst = info["Reservations"][0]["Instances"][0]
        public_ip = inst.get("PublicIpAddress", "")
        print(f"  IP pública: {public_ip}")

        # Guardar en estado
        state = load_state()
        state["instances"].append({
            "id": instance_id,
            "ip": public_ip,
            "launched_at": datetime.now().isoformat(),
            "key_file": str(key_file) if key_file else "",
        })
        save_state(state)

        return {
            "instance_id": instance_id,
            "public_ip": public_ip,
            "key_file": key_file,
        }

    except ClientError as e:
        print(f"  [!] Error lanzando instancia: {e}")
        return None

# ── Esperar que bootstrap termine ────────────────────────────
def wait_for_ready(public_ip: str, key_file: str, timeout: int = 300) -> bool:
    """Espera a que el bootstrap script termine (archivo /tmp/hackeadora_ready)."""
    if AMI_ID:
        # AMI pre-built — ya está lista
        time.sleep(15)  # Solo esperar SSH
        return True

    print(f"  Esperando bootstrap en {public_ip} (max {timeout}s)...")
    start = time.time()

    while time.time() - start < timeout:
        try:
            result = subprocess.run(
                ["ssh", "-i", key_file,
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "ConnectTimeout=10",
                 f"ubuntu@{public_ip}",
                 "test -f /tmp/hackeadora_ready && echo ready || echo waiting"],
                capture_output=True, text=True, timeout=20
            )
            if "ready" in result.stdout:
                print("  Bootstrap completado")
                return True
        except Exception:
            pass
        print("  ...", end="", flush=True)
        time.sleep(15)

    print("\n  [!] Timeout esperando bootstrap")
    return False

# ── Ejecutar comando remoto ───────────────────────────────────
def run_remote(public_ip: str, key_file: str, command: str,
               collect_file: Optional[str] = None) -> bool:
    """
    Ejecuta un comando en la instancia remota via SSH.
    Si collect_file está definido, trae el resultado de vuelta.
    """
    print(f"  [→] Ejecutando en {public_ip}:")
    print(f"      {command[:100]}...")

    # Ejecutar
    ssh_cmd = [
        "ssh", "-i", key_file,
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=30",
        "-o", "ServerAliveInterval=30",
        f"ubuntu@{public_ip}",
        f"export PATH=$PATH:/usr/local/go/bin:/root/go/bin && {command}"
    ]

    try:
        result = subprocess.run(ssh_cmd, timeout=3600)
        ok = result.returncode == 0

        # Traer resultados si se especificó archivo
        if collect_file and ok:
            remote_path = collect_file.replace("/tmp/", "/tmp/")
            scp_cmd = [
                "scp", "-i", key_file,
                "-o", "StrictHostKeyChecking=no",
                f"ubuntu@{public_ip}:{remote_path}",
                collect_file
            ]
            subprocess.run(scp_cmd, timeout=60)
            print(f"  Resultado recogido: {collect_file}")

        return ok

    except subprocess.TimeoutExpired:
        print("  [!] Timeout ejecutando comando remoto")
        return False
    except Exception as e:
        print(f"  [!] Error SSH: {e}")
        return False

# ── Terminar instancia ────────────────────────────────────────
def terminate_instance(ec2, instance_id: str):
    """Termina y destruye la instancia."""
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
        print(f"  [✓] Instancia {instance_id} terminada")

        # Actualizar estado
        state = load_state()
        state["instances"] = [
            i for i in state["instances"] if i["id"] != instance_id
        ]
        save_state(state)

    except ClientError as e:
        print(f"  [!] Error terminando {instance_id}: {e}")

def cleanup_all():
    """Termina todas las instancias de Hackeadora activas."""
    ec2 = get_ec2()
    state = load_state()

    if not state["instances"]:
        print("Sin instancias activas")
        return

    for inst in state["instances"]:
        print(f"Terminando {inst['id']} ({inst['ip']})...")
        terminate_instance(ec2, inst["id"])

    # También buscar por tag por si acaso
    try:
        running = ec2.describe_instances(
            Filters=[
                {"Name": "tag:Project", "Values": ["hackeadora"]},
                {"Name": "instance-state-name", "Values": ["running", "pending"]},
            ]
        )
        for r in running["Reservations"]:
            for i in r["Instances"]:
                iid = i["InstanceId"]
                print(f"Terminando por tag: {iid}")
                terminate_instance(ec2, iid)
    except Exception:
        pass

# ── API pública para módulos bash ─────────────────────────────
def rotate_and_exec(command: str, collect_file: Optional[str] = None,
                    use_bootstrap: bool = True) -> bool:
    """
    Función principal: lanza instancia, ejecuta, recoge, destruye.
    """
    ec2 = get_ec2()

    inst = launch_spot_instance(ec2, use_bootstrap)
    if not inst:
        print("  [!] No se pudo lanzar instancia — ejecutando localmente")
        return False

    instance_id = inst["instance_id"]
    public_ip   = inst["public_ip"]
    key_file    = inst["key_file"]

    try:
        # Esperar bootstrap
        if not wait_for_ready(public_ip, key_file):
            return False

        # Ejecutar comando
        ok = run_remote(public_ip, key_file, command, collect_file)

        # Actualizar contador
        state = load_state()
        state["request_count"] = state.get("request_count", 0) + 1
        save_state(state)

        return ok

    finally:
        # Siempre destruir la instancia
        print(f"  [→] Destruyendo instancia {instance_id}...")
        terminate_instance(ec2, instance_id)

def should_rotate(request_count: int) -> bool:
    """Devuelve True si es momento de rotar según ROTATION_INTERVAL."""
    return request_count > 0 and request_count % ROTATION_INTERVAL == 0

# ── Main ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AWS IP Rotator para Hackeadora")
    parser.add_argument("--exec",     help="Comando a ejecutar en instancia remota")
    parser.add_argument("--collect",  help="Archivo a traer de vuelta tras ejecución")
    parser.add_argument("--status",   action="store_true", help="Ver instancias activas")
    parser.add_argument("--cleanup",  action="store_true", help="Destruir todas las instancias")
    parser.add_argument("--test",     action="store_true", help="Test de conectividad AWS")
    parser.add_argument("--no-bootstrap", action="store_true", help="Usar AMI pre-built")
    args = parser.parse_args()

    if args.status:
        state = load_state()
        print(f"Instancias activas: {len(state['instances'])}")
        for i in state["instances"]:
            print(f"  {i['id']} — {i['ip']} — lanzada: {i['launched_at']}")
        print(f"Peticiones totales: {state.get('request_count', 0)}")
        return

    if args.cleanup:
        cleanup_all()
        return

    if args.test:
        print("Testando conectividad AWS...")
        try:
            ec2 = get_ec2()
            ec2.describe_regions()
            print("[✓] AWS conectado correctamente")
            ami = get_ami(ec2)
            print(f"[✓] AMI seleccionada: {ami}")
            sg = ensure_security_group(ec2)
            print(f"[✓] Security group: {sg}")
        except NoCredentialsError:
            print("[✗] Sin credenciales AWS — configura AWS_ACCESS_KEY_ID y AWS_SECRET_ACCESS_KEY")
        except Exception as e:
            print(f"[✗] Error: {e}")
        return

    if args.exec:
        ok = rotate_and_exec(
            args.exec,
            args.collect,
            use_bootstrap=not args.no_bootstrap
        )
        sys.exit(0 if ok else 1)

    parser.print_help()

if __name__ == "__main__":
    main()
