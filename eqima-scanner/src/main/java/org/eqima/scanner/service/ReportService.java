package org.eqima.scanner.service;

import com.itextpdf.io.font.constants.StandardFonts;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.eqima.scanner.entity.Finding;
import org.eqima.scanner.entity.ScanSession;
import org.eqima.scanner.repository.FindingRepository;
import org.eqima.scanner.repository.ScanSessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class ReportService {

    private static final DateTimeFormatter FMT =
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm").withZone(ZoneId.of("UTC"));

    private static final DeviceRgb HEADER_BG  = new DeviceRgb(30,  30,  60);
    private static final DeviceRgb HIGH_COLOR  = new DeviceRgb(200, 50,  50);
    private static final DeviceRgb MED_COLOR   = new DeviceRgb(220, 120, 20);
    private static final DeviceRgb LOW_COLOR   = new DeviceRgb(40,  130, 40);
    private static final DeviceRgb INFO_COLOR  = new DeviceRgb(60,  100, 180);

    private final ScanSessionRepository sessionRepo;
    private final FindingRepository findingRepo;

    public ReportService(ScanSessionRepository sessionRepo, FindingRepository findingRepo) {
        this.sessionRepo = sessionRepo;
        this.findingRepo = findingRepo;
    }

    public Mono<byte[]> generatePdf(String sessionId) {
        return Mono.fromCallable(() -> buildPdf(sessionId))
                .subscribeOn(Schedulers.boundedElastic());
    }

    private byte[] buildPdf(String sessionId) throws IOException {
        ScanSession session = sessionRepo.findById(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Session not found: " + sessionId));

        List<Finding> findings = findingRepo.findBySessionIdOrderBySeverityAscDetectedAtAsc(sessionId);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PdfWriter writer = new PdfWriter(baos);
        PdfDocument pdf = new PdfDocument(writer);
        Document doc = new Document(pdf, PageSize.A4);
        doc.setMargins(40, 50, 40, 50);

        PdfFont bold = PdfFontFactory.createFont(StandardFonts.HELVETICA_BOLD);
        PdfFont regular = PdfFontFactory.createFont(StandardFonts.HELVETICA);

        // ── En-tête ────────────────────────────────────────────────────────────
        doc.add(new Paragraph("EQIMA Security Scanner")
                .setFont(bold).setFontSize(22).setFontColor(ColorConstants.WHITE)
                .setBackgroundColor(HEADER_BG).setTextAlignment(TextAlignment.CENTER)
                .setPadding(14));

        doc.add(new Paragraph("Rapport de scan de sécurité")
                .setFont(bold).setFontSize(14).setMarginTop(8));

        doc.add(new Paragraph(String.format(
                "Cible : %s (%s)\nDébut : %s   Fin : %s\nStatut : %s   Findings : %d",
                session.getTargetName(), session.getTargetUrl(),
                session.getStartedAt() != null ? FMT.format(session.getStartedAt()) : "-",
                session.getCompletedAt() != null ? FMT.format(session.getCompletedAt()) : "-",
                session.getStatus(), session.getTotalFindings()))
                .setFont(regular).setFontSize(10).setMarginTop(4));

        // ── Résumé par sévérité ────────────────────────────────────────────────
        long high   = findingRepo.countBySessionIdAndSeverity(sessionId, Finding.Severity.HIGH);
        long medium = findingRepo.countBySessionIdAndSeverity(sessionId, Finding.Severity.MEDIUM);
        long low    = findingRepo.countBySessionIdAndSeverity(sessionId, Finding.Severity.LOW);
        long info   = findingRepo.countBySessionIdAndSeverity(sessionId, Finding.Severity.INFORMATIONAL);

        Table summary = new Table(UnitValue.createPercentArray(new float[]{25, 25, 25, 25}))
                .setWidth(UnitValue.createPercentValue(100)).setMarginTop(12);
        addSummaryCell(summary, "HIGH",          String.valueOf(high),   HIGH_COLOR, bold);
        addSummaryCell(summary, "MEDIUM",        String.valueOf(medium), MED_COLOR,  bold);
        addSummaryCell(summary, "LOW",           String.valueOf(low),    LOW_COLOR,  bold);
        addSummaryCell(summary, "INFORMATIONAL", String.valueOf(info),   INFO_COLOR, bold);
        doc.add(summary);

        // ── Tableau des findings ───────────────────────────────────────────────
        if (findings.isEmpty()) {
            doc.add(new Paragraph("Aucun finding détecté.")
                    .setFont(regular).setFontSize(11).setMarginTop(20));
        } else {
            doc.add(new Paragraph("Détail des findings")
                    .setFont(bold).setFontSize(13).setMarginTop(20));

            Table table = new Table(UnitValue.createPercentArray(new float[]{15, 35, 30, 20}))
                    .setWidth(UnitValue.createPercentValue(100)).setMarginTop(8);

            addHeaderRow(table, bold, "Sévérité", "Nom", "URL", "CWE");

            for (Finding f : findings) {
                DeviceRgb color = severityColor(f.getSeverity());
                addRow(table, regular, color,
                        f.getSeverity().name(),
                        f.getName(),
                        truncate(f.getUrl(), 60),
                        f.getCweid() != null ? "CWE-" + f.getCweid() : "-");

                // Ligne description/solution
                Cell detailCell = new Cell(1, 4)
                        .add(new Paragraph("Description : " + truncate(f.getDescription(), 300))
                                .setFont(regular).setFontSize(8))
                        .add(new Paragraph("Solution : " + truncate(f.getSolution(), 200))
                                .setFont(regular).setFontSize(8).setFontColor(ColorConstants.DARK_GRAY))
                        .setBackgroundColor(new DeviceRgb(248, 248, 252))
                        .setPadding(4);
                table.addCell(detailCell);
            }
            doc.add(table);
        }

        doc.close();
        return baos.toByteArray();
    }

    private void addSummaryCell(Table table, String label, String count,
                                 DeviceRgb color, PdfFont bold) {
        table.addCell(new Cell()
                .add(new Paragraph(label).setFont(bold).setFontSize(9)
                        .setFontColor(ColorConstants.WHITE))
                .add(new Paragraph(count).setFont(bold).setFontSize(20)
                        .setFontColor(ColorConstants.WHITE))
                .setBackgroundColor(color)
                .setTextAlignment(TextAlignment.CENTER).setPadding(8));
    }

    private void addHeaderRow(Table table, PdfFont bold, String... cols) {
        for (String col : cols) {
            table.addHeaderCell(new Cell()
                    .add(new Paragraph(col).setFont(bold).setFontSize(9)
                            .setFontColor(ColorConstants.WHITE))
                    .setBackgroundColor(HEADER_BG).setPadding(5));
        }
    }

    private void addRow(Table table, PdfFont font, DeviceRgb severityColor, String... cols) {
        boolean first = true;
        for (String col : cols) {
            Cell cell = new Cell().add(new Paragraph(col).setFont(font).setFontSize(9)).setPadding(4);
            if (first) {
                cell.setFontColor(severityColor);
                first = false;
            }
            table.addCell(cell);
        }
    }

    private DeviceRgb severityColor(Finding.Severity severity) {
        return switch (severity) {
            case HIGH          -> HIGH_COLOR;
            case MEDIUM        -> MED_COLOR;
            case LOW           -> LOW_COLOR;
            case INFORMATIONAL -> INFO_COLOR;
        };
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "…" : s;
    }
}