import json
from fpdf import FPDF
from datetime import datetime

def export_to_json(data: dict, file_path: str):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def export_to_pdf(data, output_path):
    pdf = FPDF()
    pdf.add_page()
    
    # Başlık
    pdf.set_font('helvetica', 'B', 16)
    pdf.cell(0, 10, 'Nmap Tarama Sonuclari', 0, 1, 'C')
    pdf.ln(10)
    
    # Tarih
    pdf.set_font('helvetica', 'I', 10)
    pdf.cell(0, 10, f'Tarih: {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 1, 'R')
    pdf.ln(5)
    
    # Her tarama türü için sonuçları yazdır
    for scan_type, scan_data in data.items():
        pdf.set_font('helvetica', 'B', 12)
        pdf.cell(0, 10, f'Tarama Turu: {scan_type.upper()}', 0, 1, 'L')
        pdf.ln(5)
        
        if isinstance(scan_data, dict) and "error" in scan_data:
            pdf.set_font('helvetica', 'I', 10)
            pdf.cell(0, 10, f'Hata: {scan_data["error"]}', 0, 1, 'L')
            pdf.ln(5)
            continue
            
        # Host bilgileri
        if isinstance(scan_data, dict) and "host" in scan_data:
            pdf.set_font('helvetica', 'B', 11)
            pdf.cell(0, 10, 'Host Bilgileri:', 0, 1, 'L')
            pdf.set_font('helvetica', '', 10)
            
            host_data = scan_data["host"]
            if isinstance(host_data, dict):
                for key, value in host_data.items():
                    if isinstance(value, dict):
                        pdf.cell(0, 10, f'{key}:', 0, 1, 'L')
                        for sub_key, sub_value in value.items():
                            pdf.cell(0, 10, f'  {sub_key}: {sub_value}', 0, 1, 'L')
                    else:
                        pdf.cell(0, 10, f'{key}: {value}', 0, 1, 'L')
            else:
                pdf.cell(0, 10, f'Host: {host_data}', 0, 1, 'L')
            pdf.ln(5)
        
        # Port taramaları
        if isinstance(scan_data, dict) and "ports" in scan_data:
            pdf.set_font('helvetica', 'B', 11)
            pdf.cell(0, 10, 'Port Taramalari:', 0, 1, 'L')
            pdf.set_font('helvetica', '', 10)
            
            # Tablo başlıkları
            pdf.set_fill_color(200, 200, 200)
            pdf.cell(30, 10, 'Port', 1, 0, 'C', True)
            pdf.cell(40, 10, 'Durum', 1, 0, 'C', True)
            pdf.cell(60, 10, 'Servis', 1, 0, 'C', True)
            pdf.cell(60, 10, 'Versiyon', 1, 1, 'C', True)
            
            # Port bilgileri
            ports = scan_data["ports"]
            if isinstance(ports, list):
                for port in ports:
                    if isinstance(port, dict):
                        pdf.cell(30, 10, str(port.get("port", "")), 1)
                        pdf.cell(40, 10, str(port.get("state", "")), 1)
                        pdf.cell(60, 10, str(port.get("service", "")), 1)
                        pdf.cell(60, 10, str(port.get("version", "")), 1)
                        pdf.ln()
            pdf.ln(5)
        
        # Script çıktıları
        if isinstance(scan_data, dict) and "scripts" in scan_data:
            pdf.set_font('helvetica', 'B', 11)
            pdf.cell(0, 10, 'Script Ciktilari:', 0, 1, 'L')
            pdf.set_font('helvetica', '', 10)
            
            scripts = scan_data["scripts"]
            if isinstance(scripts, dict):
                for script_name, script_output in scripts.items():
                    pdf.cell(0, 10, f'Script: {script_name}', 0, 1, 'L')
                    if isinstance(script_output, dict):
                        for key, value in script_output.items():
                            pdf.cell(0, 10, f'  {key}: {value}', 0, 1, 'L')
                    else:
                        pdf.cell(0, 10, f'  {script_output}', 0, 1, 'L')
            pdf.ln(5)
        
        # Sayfa sonu
        pdf.add_page()
    
    pdf.output(output_path)
