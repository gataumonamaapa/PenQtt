import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

class ReportGenerator:
    """
    Kelas untuk menghasilkan laporan keamanan MQTT dalam format PDF.
    
    Menggabungkan hasil pengujian dengan saran mitigasi yang dinamis
    berdasarkan hasil tersebut.
    """
    def __init__(self, path):
        self.path = path
        self.doc = SimpleDocTemplate(path, pagesize=A4)
        self.elements = []
        self.styles = getSampleStyleSheet()
        # Style khusus untuk teks di dalam sel tabel agar bisa text-wrap
        self.wrap_style = ParagraphStyle(
            name='WrapStyle',
            alignment=TA_LEFT,
            fontSize=10,
            leading=12,
            wordWrap='CJK' # CJK (Chinese, Japanese, Korean) word wrapping handles long text well
        )

    def _generate_mitigation_table(self, username, use_tls, flood_info, acl_summary, topics):
        """
        Membuat tabel saran mitigasi berdasarkan hasil pengujian.
        Logika if-else digunakan untuk memberikan saran yang relevan.
        """
        mitigation_data = [
            ["No", "Nama Modul Uji", Paragraph("Saran Mitigasi", self.wrap_style)]
        ]
        
        # 1. Logika untuk Enumerasi Topik
        # Asumsi: Jika lebih dari 10 topik ditemukan, itu dianggap banyak.
        if len(topics) > 10:
            suggestion = "Jumlah topik yang dapat diakses publik/pengguna sangat banyak. Terapkan ACL (Access Control List) untuk membatasi hak akses pengguna agar hanya bisa melihat/mengakses topik yang relevan."
        else:
            suggestion = "Jumlah topik yang dapat diakses sudah terbatas. Ini adalah praktik keamanan yang baik untuk meminimalkan permukaan serangan."
        mitigation_data.append(["1", "Enumerasi Topik", Paragraph(suggestion, self.wrap_style)])
        
        # 2. Logika untuk Brute Force
        if username:
            suggestion = "Kredensial berhasil ditemukan. Ganti kredensial dengan password yang kuat (kombinasi huruf, angka, simbol) dan pertimbangkan mekanisme 'account lockout' setelah beberapa kali gagal login."
        else:
            suggestion = "Brute force tidak berhasil. Pertahankan kebijakan kredensial yang kuat."
        mitigation_data.append(["2", "Brute Force", Paragraph(suggestion, self.wrap_style)])

        # 3. Logika untuk TLS
        if not use_tls:
            suggestion = "Broker tidak menggunakan enkripsi TLS. Segera aktifkan TLS untuk mengenkripsi seluruh komunikasi data dan mencegah serangan penyadapan (eavesdropping)."
        else:
            suggestion = "TLS sudah aktif. Ini adalah langkah keamanan fundamental yang sudah tepat untuk melindungi integritas dan kerahasiaan data."
        mitigation_data.append(["3", "TLS", Paragraph(suggestion, self.wrap_style)])

        # 4. Logika untuk Fuzzing
        suggestion = "Meskipun broker tampak tangguh terhadap Fuzzing, pastikan ada mekanisme validasi dan sanitasi input di sisi broker untuk menolak payload yang tidak sesuai format atau berpotensi berbahaya."
        mitigation_data.append(["4", "Fuzzing", Paragraph(suggestion, self.wrap_style)])

        # 5. Logika untuk Flood (DoS)
        if "Delay" in flood_info.get('reason', ''):
            suggestion = "Serangan DoS berhasil memperlambat broker. Terapkan 'rate limiting' untuk membatasi jumlah pesan dari satu klien per detik dan batasi ukuran maksimum payload yang diizinkan."
        else:
            suggestion = "Broker menunjukkan ketahanan yang baik terhadap serangan Flood (DoS). Tetap monitor performa secara berkala."
        mitigation_data.append(["5", "Flood (DoS)", Paragraph(suggestion, self.wrap_style)])

        # 6. Logika untuk QoS Delay
        suggestion = "Waktu tunda QoS terpantau normal. Pastikan performa server broker (CPU, RAM, Network) selalu dimonitor untuk menjaga latensi tetap rendah, terutama pada lingkungan produksi."
        mitigation_data.append(["6", "QoS Delay", Paragraph(suggestion, self.wrap_style)])
        
        # 7. Logika untuk ACL
        if "ACL Lemah" in acl_summary:
            suggestion = "Terdeteksi ACL yang lemah. Segera perketat aturan ACL dengan menerapkan prinsip 'least privilege': setiap pengguna hanya boleh memiliki hak publish/subscribe pada topik yang benar-benar dibutuhkan."
        else:
            suggestion = "Konfigurasi ACL sudah kuat dan membatasi akses dengan benar. Lakukan audit secara berkala untuk memastikan aturan tetap relevan."
        mitigation_data.append(["7", "ACL", Paragraph(suggestion, self.wrap_style)])

        # Membuat dan menata objek tabel mitigasi
        table = Table(mitigation_data, colWidths=[30, 100, 350])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        return table

    def generate(self, broker_ip, username, password, topics, fuzz_count, flood_info,
                 qos_delay_summary, use_tls, acl_summary):
        """
        Metode utama untuk membangun seluruh dokumen PDF.
        """
        # --- Bagian 1: Judul dan Informasi Umum ---
        self.elements.append(Paragraph("<b>Laporan Pengujian Keamanan MQTT</b>", self.styles['Title']))
        self.elements.append(Spacer(1, 12))
        self.elements.append(Paragraph(f"<b>Broker IP:</b> {broker_ip}", self.styles['Normal']))
        self.elements.append(Paragraph(f"<b>Username:</b> {username if username else '-'}", self.styles['Normal']))
        self.elements.append(Paragraph(f"<b>Password:</b> {password if password else '-'}", self.styles['Normal']))
        self.elements.append(Paragraph(f"<b>TLS Aktif:</b> {'Ya' if use_tls else 'Tidak'}", self.styles['Normal']))
        self.elements.append(Spacer(1, 12))

        # --- Bagian 2: Tabel Hasil Pengujian ---
        self.elements.append(Paragraph("<b>Hasil Pengujian</b>", self.styles['Heading2']))
        self.elements.append(Spacer(1, 6))
        qos_result = f"QoS 0: {qos_delay_summary.get('0', '-')}s, QoS 1: {qos_delay_summary.get('1', '-')}s, QoS 2: {qos_delay_summary.get('2', '-')}s"
        data = [
            ["Jenis Pengujian", "Deskripsi Singkat", "Hasil Utama"],
            ["Enumerasi Topik", Paragraph("Mencoba akses semua topik menggunakan kredensial tersedia", self.wrap_style),
             Paragraph(f"{len(topics)} topik ditemukan", self.wrap_style)],
            ["Brute Force", Paragraph("Mencoba semua kombinasi username/password", self.wrap_style),
             Paragraph(f"{username}:{password}" if username and password else "-", self.wrap_style)],
            ["TLS", Paragraph("Analisis apakah broker menggunakan TLS", self.wrap_style),
             Paragraph("Ya" if use_tls else "Tidak", self.wrap_style)],
            ["Fuzzing", Paragraph(f"Kirim {fuzz_count} payload acak ke topik MQTT", self.wrap_style),
             Paragraph("Berhasil dikirim ke semua topik", self.wrap_style)],
            ["Flood (DoS)", Paragraph("Kirim pesan masif untuk menguji ke­ tahanan broker", self.wrap_style),
             Paragraph(f"Dikirim {flood_info.get('total_messages', '-')} pesan.<br/>Dihentikan karena: {flood_info.get('reason', '-')}",self.wrap_style)],
            ["QoS Delay", Paragraph("Ukur waktu kirim pesan pada berbagai QoS", self.wrap_style),
             Paragraph(qos_result, self.wrap_style)],
            ["ACL", Paragraph("Analisis apakah broker memiliki kontrol akses", self.wrap_style),
             Paragraph(acl_summary, self.wrap_style)]
        ]
        table = Table(data, colWidths=[100, 180, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        self.elements.append(table)
        self.elements.append(Spacer(1, 24))

        # --- Bagian 3: Tabel Saran Mitigasi ---
        self.elements.append(Paragraph("<b>Saran Mitigasi Keamanan</b>", self.styles['Heading2']))
        self.elements.append(Spacer(1, 6))
        mitigation_table = self._generate_mitigation_table(username, use_tls, flood_info, acl_summary, topics)
        self.elements.append(mitigation_table)
        
        # --- Finalisasi: Membangun Dokumen PDF ---
        self.doc.build(self.elements)
        print(f"Laporan berhasil dibuat di: {self.path}")
        return self.path

# --- Contoh Penggunaan ---
if __name__ == '__main__':
    # Data dummy hasil pengujian (sesuai dengan contoh gambar)
    report_data = {
        "broker_ip": "192.168.100.75",
        "username": "raspiuser",
        "password": "raspiuser",
        "topics": ["aclcheck/test/0"], # Ditemukan 1 topik
        "fuzz_count": 20,
        "flood_info": {
            "total_messages": 1555,
            "reason": "Delay melebihi 1.0s"
        },
        "qos_delay_summary": {
            '0': '0.0002', '1': '0.0045', '2': '0.0056'
        },
        "use_tls": True,
        "acl_summary": "[✔] ACL Lemah! Pesan berhasil diterima dari topik terlarang."
    }

    # Membuat nama file laporan
    file_name = f"laporan_{report_data['broker_ip'].replace('.', '_')}.pdf"

    # Membuat instance generator dan menghasilkan laporan
    report_generator = ReportGenerator(file_name)
    report_generator.generate(**report_data)