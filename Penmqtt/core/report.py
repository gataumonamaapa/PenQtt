import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

class ReportGenerator:
    def __init__(self, path):
        self.path = path
        self.doc = SimpleDocTemplate(path, pagesize=A4)
        self.elements = []
        self.styles = getSampleStyleSheet()
        self.wrap_style = ParagraphStyle(
            name='WrapStyle',
            alignment=TA_LEFT,
            fontSize=10,
            leading=12,
            wordWrap='CJK'
        )

    def generate(self, broker_ip, username, password, topics, fuzz_count, flood_info,
                 qos_delay_summary, use_tls, acl_summary):
        self.elements.append(Paragraph("<b>Laporan Pengujian Keamanan MQTT</b>", self.styles['Title']))
        self.elements.append(Spacer(1, 12))

        self.elements.append(Paragraph(f"<b>Broker IP:</b> {broker_ip}", self.styles['Normal']))
        self.elements.append(Paragraph(f"<b>Username:</b> {username if username else '-'}", self.styles['Normal']))
        self.elements.append(Paragraph(f"<b>Password:</b> {password if password else '-'}", self.styles['Normal']))
        self.elements.append(Paragraph(f"<b>TLS Aktif:</b> {'Ya' if use_tls else 'Tidak'}", self.styles['Normal']))
        self.elements.append(Spacer(1, 12))

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
             Paragraph(f"Dikirim {flood_info.get('total_messages', '-')} pesan ke {flood_info.get('total_topics', '-')} topik "f"(~{flood_info.get('payload_size_kb', '-')} KB).<br/>"f"Dihentikan karena: {flood_info.get('reason', '-')}",self.wrap_style)],
            ["QoS Delay", Paragraph("Ukur waktu kirim pesan pada berbagai QoS", self.wrap_style),
             Paragraph(qos_result, self.wrap_style)],
            ["ACL", Paragraph("Analisis apakah broker memiliki kontrol akses", self.wrap_style),
             Paragraph(acl_summary, self.wrap_style)]
        ]

        table = Table(data, colWidths=[100, 160, 250])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        if acl_summary and "ACL Kuat" in acl_summary:
            self.elements.append(Spacer(1, 12))
            self.elements.append(Paragraph(
                "<i>Catatan:</i> Beberapa pengujian seperti DoS dan QoS Delay tidak dijalankan atau gagal karena broker membatasi akses wildcard melalui ACL (Access Control List).",
                self.styles['Normal']
            ))
        self.elements.append(table)
        self.doc.build(self.elements)

        return self.path
