package org.eqima.scanner.controller;

import org.eqima.scanner.entity.AttackFinding;
import org.eqima.scanner.entity.AttackScanJob;
import org.eqima.scanner.entity.DiscoveredAsset;
import org.eqima.scanner.repository.AttackFindingRepository;
import org.eqima.scanner.repository.AttackScanJobRepository;
import org.eqima.scanner.repository.DiscoveredAssetRepository;
import org.eqima.scanner.service.AttackSurfaceOrchestrator;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/surface")
public class AttackSurfaceV2Controller {

    private final AttackSurfaceOrchestrator   orchestrator;
    private final AttackScanJobRepository     jobRepo;
    private final DiscoveredAssetRepository   assetRepo;
    private final AttackFindingRepository     findingRepo;

    public AttackSurfaceV2Controller(
        AttackSurfaceOrchestrator orchestrator,
        AttackScanJobRepository jobRepo,
        DiscoveredAssetRepository assetRepo,
        AttackFindingRepository findingRepo
    ) {
        this.orchestrator = orchestrator;
        this.jobRepo      = jobRepo;
        this.assetRepo    = assetRepo;
        this.findingRepo  = findingRepo;
    }

    /** POST /v1/surface/scan?domain=example.com → starts scan, returns jobId */
    @PostMapping("/scan")
    public Mono<Map<String, String>> startScan(@RequestParam String domain) {
        String jobId = orchestrator.startScan(domain);
        return Mono.just(Map.of("jobId", jobId, "domain", domain));
    }

    /** GET /v1/surface/scan/{id}/stream → SSE real-time events */
    @GetMapping(value = "/scan/{id}/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> stream(@PathVariable String id) {
        return orchestrator.stream(id);
    }

    /** GET /v1/surface/scan/{id} → job status + summary */
    @GetMapping("/scan/{id}")
    public Mono<AttackScanJob> getJob(@PathVariable String id) {
        return Mono.justOrEmpty(jobRepo.findById(id));
    }

    /** GET /v1/surface/scan/{id}/results → assets + findings */
    @GetMapping("/scan/{id}/results")
    public Mono<Map<String, Object>> getResults(@PathVariable String id) {
        List<DiscoveredAsset> assets   = assetRepo.findByJobIdOrderByRiskScoreDesc(id);
        List<AttackFinding>   findings = findingRepo.findByJobIdOrderBySeverityAscTitleAsc(id);
        return Mono.just(Map.of("assets", assets, "findings", findings));
    }

    /** GET /v1/surface/scans → list all jobs */
    @GetMapping("/scans")
    public Mono<List<AttackScanJob>> listJobs() {
        return Mono.just(jobRepo.findAllByOrderByStartedAtDesc());
    }
}