from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from datetime import datetime

class ReportGenerator:
    def __init__(self, filename, logger=None):
        self.filename = filename
        self.logger = logger

    def log(self, msg):
        if self.logger:
            self.logger(msg)

    def generate(self, broker_ip, username, password, topics,
                 fuzz_count, flood_info, qos_delay_summary,
                 use_tls=False, acl_summary=False, device_name="Perangkat IoT"):

        doc = SimpleDocTemplate(self.filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("LAPORAN HASIL SIMULASI PENGUJIAN KEAMANAN MQTT", styles['Title']))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Nama Perangkat: {device_name}", styles['Normal']))
        story.append(Paragraph(f"IP Broker: {broker_ip}", styles['Normal']))
        story.append(Paragraph(f"Tanggal: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 12))

        story.append(Paragraph("<b>Sistem Keamanan yang Terdeteksi</b>", styles['Heading3']))
        if username and password:
            story.append(Paragraph("- Username dan Password", styles['Normal']))
        if use_tls:
            story.append(Paragraph("- TLS (Transport Layer Security)", styles['Normal']))
        if acl_summary and "ACL Kuat" in acl_summary:
            story.append(Paragraph("- ACL (Access Control List)", styles['Normal']))
        story.append(Spacer(1, 12))

        story.append(Paragraph("<b>Rincian Hasil Pengujian</b>", styles['Heading3']))

        # QoS delay hasil (tandai jika -1 = Gagal ACL)
        qos_str = ", ".join([
            f"QoS {qos}: {'Gagal (ACL)' if delay == -1 else f'{delay:.3f}s'}"
            for qos, delay in qos_delay_summary.items()
        ])

        # DoS string
        if flood_info["topic_count"] == 0:
            dos_result = "Tidak dilakukan (ACL aktif)"
        else:
            dos_result = (
                f"Dikirim {flood_info['messages_per_topic']} pesan ke "
                f"{flood_info['topic_count']} topik "
                f"(≈{flood_info.get('payload_size_kb', 0):.1f} KB). "
                f"Dihentikan karena: {flood_info.get('reason', 'tidak diketahui')}."
            )


        table_data = [
            ["Jenis Pengujian", "Deskripsi Singkat", "Hasil Utama"],
            ["Enumerasi Topik", "Mencoba akses semua topik menggunakan kredensial tersedia", f"{len(topics)} topik ditemukan"],
            ["Brute Force", "Mencoba semua kombinasi username/password", f"{username}:{password}" if username and password else "Tidak ditemukan"],
            ["TLS Detection", "Analisis apakah broker menggunakan TLS", "Ya" if use_tls else "Tidak"],
            ["Fuzzing Payload", f"Kirim {fuzz_count} payload acak ke topik MQTT", "Berhasil dikirim ke semua topik"],
            ["Subscribe Flood (DoS)", "Kirim pesan masif untuk menguji ketahanan broker", dos_result],
            ["QoS Delay Test", "Ukur waktu kirim pesan pada berbagai QoS", qos_str]
        ]

        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ]))
        story.append(table)

        # Tambahkan catatan jika ACL membatasi pengujian
        if acl_summary and "ACL Kuat" in acl_summary:
            story.append(Spacer(1, 12))
            story.append(Paragraph(
                "<i>Catatan:</i> Beberapa pengujian seperti DoS dan QoS Delay tidak dijalankan atau gagal karena broker membatasi akses wildcard melalui ACL (Access Control List).",
                styles['Normal']
            ))

        doc.build(story)
        print(f"[✓] Laporan RPP-style PDF disimpan sebagai {self.filename}")
