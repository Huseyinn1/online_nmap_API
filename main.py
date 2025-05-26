from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from uuid import uuid4
import base64
import os
from models import TargetRequest, ScanScriptRequest, ScanTypeRequest, PortRangeRequest
from scanners.core import run_nmap
from utils.export import export_to_json, export_to_pdf

app = FastAPI()

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tüm originlere izin ver
    allow_credentials=True,
    allow_methods=["*"],  # Tüm HTTP metodlarına izin ver
    allow_headers=["*"],  # Tüm headerlara izin ver
)

def run_generic(ip, options):
    try:
        return run_nmap(str(ip), options)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/nmap/discovery")
def discovery(req: TargetRequest):
    return run_generic(req.ip, "-sn")

@app.post("/nmap/os")
def os_detection(req: TargetRequest):
    return run_generic(req.ip, "-O")

@app.post("/nmap/vuln")
def vuln_scan(req: TargetRequest):
    return run_generic(req.ip, "--script vuln")

@app.post("/nmap/script-scan")
def script_scan(req: ScanScriptRequest):
    return run_generic(req.ip, f"--script {req.script_name}")

@app.post("/nmap/full-scan")
def full_scan(req: TargetRequest):
    options = "-sS -sV -O --script vuln,dns-brute,http-enum --traceroute -T4"
    return run_generic(req.ip, options)

@app.post("/nmap/light")
def light_scan(req: TargetRequest):
    """Hızlı tarama: Sadece yaygın portlar ve temel servis tespiti"""
    options = "-sV -T4 -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    return run_generic(req.ip, options)

@app.post("/nmap/medium")
def medium_scan(req: TargetRequest):
    """Orta seviye tarama: Daha fazla port ve servis tespiti"""
    options = "-sV -T4 -p 20-25,53,80,110-111,135-139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
    return run_generic(req.ip, options)

@app.post("/nmap/heavy")
def heavy_scan(req: TargetRequest):
    """Ağır tarama: Tüm portlar ve detaylı servis tespiti"""
    options = "-sV -T4 -p-"
    return run_generic(req.ip, options)

@app.post("/nmap/vuln-light")
def vuln_light_scan(req: TargetRequest):
    """Hafif zafiyet taraması: Sadece yaygın portlarda temel zafiyet kontrolleri"""
    options = "-sV -T4 --script vuln -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    return run_generic(req.ip, options)

@app.post("/nmap/vuln-medium")
def vuln_medium_scan(req: TargetRequest):
    """Orta seviye zafiyet taraması: Daha fazla port ve script"""
    options = "-sV -T4 --script vuln,auth,default -p 20-25,53,80,110-111,135-139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
    return run_generic(req.ip, options)

@app.post("/nmap/vuln-heavy")
def vuln_heavy_scan(req: TargetRequest):
    """Ağır zafiyet taraması: Tüm portlar ve tüm zafiyet scriptleri"""
    options = "-sV -T4 --script vuln,auth,default,version -p-"
    return run_generic(req.ip, options)

@app.post("/nmap/web")
def web_scan(req: TargetRequest):
    """Web sunucu taraması: HTTP/HTTPS portları ve web zafiyetleri"""
    options = "-sV -T4 --script http-* -p 80,443,8080,8443,8888,9000"
    return run_generic(req.ip, options)

@app.post("/nmap/db")
def db_scan(req: TargetRequest):
    """Veritabanı taraması: Yaygın veritabanı portları"""
    options = "-sV -T4 --script db-* -p 1433,3306,5432,6379,27017"
    return run_generic(req.ip, options)

@app.post("/nmap/custom")
def custom_scan(req: ScanScriptRequest):
    """Özel tarama: Kullanıcının belirlediği script ve portlar"""
    return run_generic(req.ip, f"--script {req.script_name}")

@app.post("/nmap/export-pdf")
def scan_and_export(req: TargetRequest):
    try:
        scan_data = run_nmap(str(req.ip), "-sV -T4")
        scan_id = str(uuid4())
        export_to_pdf(scan_data, f"exports/{scan_id}.pdf")
        return {"scan_id": scan_id, "message": "PDF oluşturuldu"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/nmap/scan")
def scan_by_type(req: ScanTypeRequest):
    """Seçilen tarama türlerine göre ilgili taramaları çalıştırır ve sonuçları birleştirir"""
    # Timing parametresini kontrol et
    timing = req.timing if req.timing in ["T0", "T1", "T2", "T3", "T4", "T5"] else "T3"
    
    # Port aralığı kontrolü
    port_range = None
    if req.port_range and req.port_range.strip() and req.port_range.lower() != "string":
        # Port aralığı formatını kontrol et
        if any(c.isdigit() for c in req.port_range):
            port_range = req.port_range
    
    scan_types = {
        "discovery": lambda ip: run_generic(ip, f"-{timing} -sn"),
        "os": lambda ip: run_generic(ip, f"-{timing} -O"),
        "light": lambda ip: run_generic(ip, f"-{timing} -sV -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"),
        "medium": lambda ip: run_generic(ip, f"-{timing} -sV -p 20-25,53,80,110-111,135-139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"),
        "heavy": lambda ip: run_generic(ip, f"-{timing} -sV -p-"),
        "vuln-light": lambda ip: run_generic(ip, f"-{timing} -sV --script vuln -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"),
        "vuln-medium": lambda ip: run_generic(ip, f"-{timing} -sV --script vuln,auth,default -p 20-25,53,80,110-111,135-139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"),
        "vuln-heavy": lambda ip: run_generic(ip, f"-{timing} -sV --script vuln,auth,default,version -p-"),
        "web": lambda ip: run_generic(ip, f"-{timing} -sV --script http-* -p 80,443,8080,8443,8888,9000"),
        "db": lambda ip: run_generic(ip, f"-{timing} -sV --script db-* -p 1433,3306,5432,6379,27017"),
        "full": lambda ip: run_generic(ip, f"-{timing} -sS -sV -O --script vuln,dns-brute,http-enum --traceroute"),
        "security": lambda ip: run_generic(ip, f"-{timing} -sV --script auth,vuln,default -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"),
        "service-version": lambda ip: run_generic(ip, f"-{timing} -sV --version-intensity 9 -p-"),
        "ssl": lambda ip: run_generic(ip, f"-{timing} -sV --script ssl-* -p 443,465,993,995,8443"),
        "dns": lambda ip: run_generic(ip, f"-{timing} -sV --script dns-* -p 53"),
        "smtp": lambda ip: run_generic(ip, f"-{timing} -sV --script smtp-* -p 25,465,587"),
        "ftp": lambda ip: run_generic(ip, f"-{timing} -sV --script ftp-* -p 21,2121"),
        "smb": lambda ip: run_generic(ip, f"-{timing} -sV --script smb-* -p 139,445"),
        "quick": lambda ip: run_generic(ip, f"-{timing} -sV --top-ports 100"),
        "full-security": lambda ip: run_generic(ip, f"-{timing} -sV --script auth,vuln,default,version,discovery -p-"),
        "port-scan": lambda ip: run_generic(ip, f"-{timing} -sS")  # Sadece port taraması
    }
    
    # Geçersiz tarama türlerini kontrol et
    invalid_types = [st for st in req.scan_types if st not in scan_types]
    if invalid_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Geçersiz tarama türleri: {', '.join(invalid_types)}. Kullanılabilir türler: {', '.join(scan_types.keys())}"
        )
    
    # Tüm taramaları çalıştır ve sonuçları birleştir
    results = {}
    for scan_type in req.scan_types:
        try:
            # Eğer geçerli bir port aralığı belirtilmişse, tarama komutuna ekle
            if port_range:
                base_options = scan_types[scan_type](req.ip)
                # Port aralığını ekle
                if "-p" in base_options:
                    options = base_options.replace("-p", f"-p{port_range}")
                else:
                    options = f"{base_options} -p{port_range}"
                results[scan_type] = run_generic(req.ip, options)
            else:
                results[scan_type] = scan_types[scan_type](req.ip)
        except Exception as e:
            results[scan_type] = {"error": str(e)}
    
    return results

@app.post("/nmap/scan-and-export")
def scan_and_export_by_type(req: ScanTypeRequest):
    """Seçilen tarama türlerine göre tarama yapar ve PDF olarak dışa aktarır"""
    # Önce taramaları yap
    scan_results = scan_by_type(req)
    
    # PDF oluştur
    scan_id = str(uuid4())
    pdf_path = f"exports/{scan_id}.pdf"
    export_to_pdf(scan_results, pdf_path)
    
    # PDF'i base64'e çevir
    with open(pdf_path, "rb") as pdf_file:
        pdf_base64 = base64.b64encode(pdf_file.read()).decode()
    
    return {
        "scan_id": scan_id,
        "message": "PDF oluşturuldu",
        "pdf_base64": pdf_base64,  # Base64 formatında PDF
        "scan_results": scan_results
    }

@app.post("/nmap/security")
def security_scan(req: TargetRequest):
    """Güvenlik taraması: Temel güvenlik kontrolleri"""
    options = "-sV -T4 --script auth,vuln,default -p 21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
    return run_generic(req.ip, options)

@app.post("/nmap/service-version")
def service_version_scan(req: TargetRequest):
    """Servis versiyon taraması: Detaylı servis ve versiyon bilgisi"""
    options = "-sV -T4 --version-intensity 9 -p-"
    return run_generic(req.ip, options)

@app.post("/nmap/ssl")
def ssl_scan(req: TargetRequest):
    """SSL/TLS taraması: SSL/TLS zafiyetleri ve sertifika bilgileri"""
    options = "-sV -T4 --script ssl-* -p 443,465,993,995,8443"
    return run_generic(req.ip, options)

@app.post("/nmap/dns")
def dns_scan(req: TargetRequest):
    """DNS taraması: DNS sunucu ve kayıt bilgileri"""
    options = "-sV -T4 --script dns-* -p 53"
    return run_generic(req.ip, options)

@app.post("/nmap/smtp")
def smtp_scan(req: TargetRequest):
    """SMTP taraması: E-posta sunucu zafiyetleri"""
    options = "-sV -T4 --script smtp-* -p 25,465,587"
    return run_generic(req.ip, options)

@app.post("/nmap/ftp")
def ftp_scan(req: TargetRequest):
    """FTP taraması: FTP sunucu zafiyetleri"""
    options = "-sV -T4 --script ftp-* -p 21,2121"
    return run_generic(req.ip, options)

@app.post("/nmap/smb")
def smb_scan(req: TargetRequest):
    """SMB taraması: Windows paylaşım zafiyetleri"""
    options = "-sV -T4 --script smb-* -p 139,445"
    return run_generic(req.ip, options)

@app.post("/nmap/port-range")
def port_range_scan(req: PortRangeRequest):
    """Port aralığı taraması: Belirli port aralığında tarama"""
    options = f"-sV -T4 -p{req.start_port}-{req.end_port}"
    return run_generic(req.ip, options)

@app.post("/nmap/quick")
def quick_scan(req: TargetRequest):
    """Hızlı tarama: En yaygın 100 port"""
    options = "-sV -T4 --top-ports 100"
    return run_generic(req.ip, options)

@app.post("/nmap/full-security")
def full_security_scan(req: TargetRequest):
    """Tam güvenlik taraması: Tüm portlar ve güvenlik scriptleri"""
    options = "-sV -T4 --script auth,vuln,default,version,discovery -p-"
    return run_generic(req.ip, options)

