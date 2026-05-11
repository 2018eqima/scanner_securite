package org.eqima.scanner.controller;

import com.fasterxml.jackson.databind.JsonNode;
import org.eqima.scanner.dto.FindingDto;
import org.eqima.scanner.dto.ScanEvent;
import org.eqima.scanner.dto.ScanSessionDto;
import org.eqima.scanner.dto.StartScanRequest;
import org.eqima.scanner.service.AttackSurfaceService;
import org.eqima.scanner.service.ReportService;
import org.eqima.scanner.service.ScanService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/v1/scans")
public class ScanController {

    private final ScanService scanService;
    private final ReportService reportService;
    private final AttackSurfaceService attackSurfaceService;

    public ScanController(ScanService scanService, ReportService reportService,
                          AttackSurfaceService attackSurfaceService) {
        this.scanService = scanService;
        this.reportService = reportService;
        this.attackSurfaceService = attackSurfaceService;
    }

    /** POST /v1/scans → démarre un scan, retourne 201 avec le sessionId */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<ScanSessionDto> startScan(@RequestBody StartScanRequest request) {
        return scanService.startScan(request).map(ScanSessionDto::from);
    }

    /** GET /v1/scans → liste toutes les sessions, plus récentes en premier */
    @GetMapping
    public Mono<List<ScanSessionDto>> listSessions() {
        return scanService.getAllSessions()
                .map(sessions -> sessions.stream().map(ScanSessionDto::from).toList());
    }

    /** GET /v1/scans/{id} → détail d'une session */
    @GetMapping("/{id}")
    public Mono<ScanSessionDto> getSession(@PathVariable String id) {
        return scanService.getSession(id).map(ScanSessionDto::from);
    }

    /** GET /v1/scans/{id}/findings → liste les findings d'une session */
    @GetMapping("/{id}/findings")
    public Mono<List<FindingDto>> getFindings(@PathVariable String id) {
        return scanService.getFindings(id)
                .map(findings -> findings.stream().map(FindingDto::from).toList());
    }

    /** GET /v1/scans/{id}/events → SSE live stream des événements du scan */
    @GetMapping(value = "/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<ScanEvent>> streamEvents(@PathVariable String id) {
        return scanService.getEvents(id)
                .map(event -> ServerSentEvent.<ScanEvent>builder()
                        .id(event.sessionId() + "-" + event.type())
                        .event(event.type())
                        .data(event)
                        .build());
    }

    /** GET /v1/scans/{id}/attack-surface → surface d'attaque via ZAP */
    @GetMapping("/{id}/attack-surface")
    public Mono<JsonNode> getAttackSurface(@PathVariable String id) {
        return attackSurfaceService.getAttackSurface(id);
    }

    /** GET /v1/scans/{id}/report → télécharge le rapport PDF iText7 */
    @GetMapping(value = "/{id}/report", produces = MediaType.APPLICATION_PDF_VALUE)
    public Mono<ResponseEntity<byte[]>> downloadReport(@PathVariable String id) {
        return reportService.generatePdf(id)
                .map(bytes -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION,
                                "attachment; filename=\"eqima-report-" + id + ".pdf\"")
                        .contentType(MediaType.APPLICATION_PDF)
                        .body(bytes));
    }
}