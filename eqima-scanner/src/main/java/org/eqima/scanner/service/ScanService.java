package org.eqima.scanner.service;

import org.eqima.scanner.dto.ScanEvent;
import org.eqima.scanner.dto.StartScanRequest;
import org.eqima.scanner.entity.Finding;
import org.eqima.scanner.entity.ScanSession;
import org.eqima.scanner.repository.FindingRepository;
import org.eqima.scanner.repository.ScanSessionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.core.scheduler.Schedulers;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanSessionRepository sessionRepo;
    private final FindingRepository findingRepo;
    private final ZapService zapService;

    // Sinks actifs par sessionId — supprimés à la fin du scan
    private final Map<String, Sinks.Many<ScanEvent>> activeSinks = new ConcurrentHashMap<>();

    public ScanService(ScanSessionRepository sessionRepo,
                       FindingRepository findingRepo,
                       ZapService zapService) {
        this.sessionRepo = sessionRepo;
        this.findingRepo = findingRepo;
        this.zapService = zapService;
    }

    public Mono<ScanSession> startScan(StartScanRequest request) {
        return Mono.fromCallable(() -> {
            String url = request.url();
            if (url == null || url.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "URL requise");
            }
            // Normaliser l'URL (ajouter https:// si absent)
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                url = "https://" + url;
            }

            // Dériver le nom depuis l'URL si non fourni
            String name = (request.name() != null && !request.name().isBlank())
                    ? request.name()
                    : URI.create(url).getHost();

            ScanSession session = new ScanSession();
            session.setId(UUID.randomUUID().toString());
            session.setTargetId(UUID.randomUUID().toString());
            session.setTargetName(name);
            session.setTargetUrl(url);
            session.setStatus(ScanSession.Status.PENDING);
            session.setStartedAt(Instant.now());

            ScanSession saved = sessionRepo.save(session);

            Sinks.Many<ScanEvent> sink = Sinks.many().multicast().onBackpressureBuffer(256);
            activeSinks.put(saved.getId(), sink);

            final String finalUrl = url;
            // Lance le scan dans un thread virtuel Java 21
            Thread.ofVirtual()
                    .name("scan-" + saved.getId())
                    .start(() -> runScan(saved, sink, finalUrl));

            return saved;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public Flux<ScanEvent> getEvents(String sessionId) {
        Sinks.Many<ScanEvent> sink = activeSinks.get(sessionId);
        if (sink != null) {
            return sink.asFlux();
        }
        // Session terminée : on vérifie en base et on renvoie un événement final
        return Mono.fromCallable(() -> sessionRepo.findById(sessionId))
                .subscribeOn(Schedulers.boundedElastic())
                .flatMapMany(opt -> opt
                        .map(s -> Flux.just(new ScanEvent(sessionId, "COMPLETED",
                                "Scan already completed", 100, null)))
                        .orElse(Flux.error(new ResponseStatusException(HttpStatus.NOT_FOUND,
                                "Session not found: " + sessionId))));
    }

    public Mono<ScanSession> getSession(String sessionId) {
        return Mono.fromCallable(() -> sessionRepo.findById(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Session not found: " + sessionId)))
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<List<ScanSession>> getAllSessions() {
        return Mono.fromCallable(sessionRepo::findAllByOrderByStartedAtDesc)
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<List<Finding>> getFindings(String sessionId) {
        return Mono.fromCallable(() -> findingRepo.findBySessionIdOrderBySeverityAscDetectedAtAsc(sessionId))
                .subscribeOn(Schedulers.boundedElastic());
    }

    // ── Exécution du scan (thread virtuel) ──────────────────────────────────────

    private void runScan(ScanSession session, Sinks.Many<ScanEvent> sink, String url) {
        try {
            updateStatus(session, ScanSession.Status.RUNNING, 0);
            emit(sink, session.getId(), "STARTED", "Scan démarré pour " + session.getTargetName(), 0);

            // ── Phase Spider ──────────────────────────────────────────────────
            emit(sink, session.getId(), "SPIDER_PROGRESS", "Spider en cours : " + url, 0);
            String spiderId = zapService.startSpider(url).block();
            session.setZapSpiderId(spiderId);

            pollProgress(spiderId, "SPIDER_PROGRESS", session, sink,
                    (id) -> zapService.getSpiderProgress(id).block());

            // ── Phase Scan actif ──────────────────────────────────────────────
            emit(sink, session.getId(), "SCAN_PROGRESS", "Scan actif en cours : " + url, 0);
            String scanId = zapService.startActiveScan(url).block();
            session.setZapScanId(scanId);
            sessionRepo.save(session);

            pollProgress(scanId, "SCAN_PROGRESS", session, sink,
                    (id) -> zapService.getScanProgress(id).block());

            // ── Collecte des alertes ──────────────────────────────────────────
            emit(sink, session.getId(), "SCAN_PROGRESS", "Collecte des findings...", 95);
            List<Finding> findings = zapService.getAlerts(url, session.getId()).block();
            if (findings == null) findings = List.of();

            if (!findings.isEmpty()) {
                findingRepo.saveAll(findings);
            }

            // ── Finalisation ──────────────────────────────────────────────────
            session.setTotalFindings(findings.size());
            session.setStatus(ScanSession.Status.COMPLETED);
            session.setCompletedAt(Instant.now());
            session.setProgress(100);
            sessionRepo.save(session);

            emit(sink, session.getId(), "COMPLETED",
                    "Scan terminé — " + findings.size() + " finding(s)", 100);

        } catch (Exception e) {
            log.error("Erreur scan session {}", session.getId(), e);
            session.setStatus(ScanSession.Status.FAILED);
            session.setCompletedAt(Instant.now());
            sessionRepo.save(session);
            emit(sink, session.getId(), "ERROR", e.getMessage(), null);
        } finally {
            sink.tryEmitComplete();
            activeSinks.remove(session.getId());
        }
    }

    @FunctionalInterface
    private interface ProgressSupplier {
        Integer get(String id) throws Exception;
    }

    private void pollProgress(String id, String eventType, ScanSession session,
                               Sinks.Many<ScanEvent> sink, ProgressSupplier progressSupplier) {
        while (true) {
            try {
                Integer progress = progressSupplier.get(id);
                if (progress == null) break;

                session.setProgress(progress);
                sessionRepo.save(session);
                emit(sink, session.getId(), eventType, null, progress);

                if (progress >= 100) break;
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.warn("Erreur polling {} : {}", id, e.getMessage());
                break;
            }
        }
    }

    private void emit(Sinks.Many<ScanEvent> sink, String sessionId,
                      String type, String message, Integer progress) {
        sink.tryEmitNext(new ScanEvent(sessionId, type, message, progress, null));
    }

    private void updateStatus(ScanSession session, ScanSession.Status status, int progress) {
        session.setStatus(status);
        session.setProgress(progress);
        sessionRepo.save(session);
    }
}