import subprocess, tempfile, json
from uuid import uuid4
import xmltodict

def run_nmap(ip: str, options: str) -> dict:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        cmd = f"nmap {options} -oX {tmp.name} {ip}"
        process = subprocess.run(cmd.split(), capture_output=True, text=True)

        if process.returncode != 0:
            raise RuntimeError(process.stderr)

        with open(tmp.name, 'r') as f:
            xml_data = f.read()
            result = xmltodict.parse(xml_data)
            
            # Daha okunabilir formata dönüştürme
            formatted_result = {
                "host": result["nmaprun"]["host"]["hostnames"]["hostname"]["@name"],
                "ip": result["nmaprun"]["host"]["address"]["@addr"],
                "status": result["nmaprun"]["host"]["status"]["@state"],
                "ports": [],
                "os": None
            }
            
            # Port bilgilerini ekle
            if "ports" in result["nmaprun"]["host"] and "port" in result["nmaprun"]["host"]["ports"]:
                for port in result["nmaprun"]["host"]["ports"]["port"]:
                    port_info = {
                        "port": port["@portid"],
                        "state": port["state"]["@state"],
                        "service": port.get("service", {}).get("@name", "unknown")
                    }
                    formatted_result["ports"].append(port_info)
            
            # OS bilgisini ekle
            if "os" in result["nmaprun"]["host"] and "osmatch" in result["nmaprun"]["host"]["os"]:
                formatted_result["os"] = result["nmaprun"]["host"]["os"]["osmatch"]["@name"]

    return formatted_result
