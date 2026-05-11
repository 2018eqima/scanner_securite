package org.eqima.scanner.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.eqima.scanner.service.OpenVasService;
import org.eqima.scanner.service.ThreatIntelService;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/v1/infra")
public class InfraController {

    private final OpenVasService openVasService;
    private final ThreatIntelService threatIntelService;

    public InfraController(OpenVasService openVasService, ThreatIntelService threatIntelService) {
        this.openVasService = openVasService;
        this.threatIntelService = threatIntelService;
    }

    /** GET /v1/infra/status → état de GVM/OpenVAS */
    @GetMapping("/status")
    public Mono<ObjectNode> status() {
        return openVasService.getStatus();
    }

    /** GET /v1/infra/tasks → liste des tâches de scan */
    @GetMapping("/tasks")
    public Mono<JsonNode> tasks() {
        return openVasService.getTasks();
    }

    /** POST /v1/infra/scan → lance un scan infra */
    @PostMapping("/scan")
    public Mono<ObjectNode> startScan(@RequestBody StartInfraScanRequest req) {
        return openVasService.startScan(req.target(), req.name());
    }

    /** GET /v1/infra/tasks/{id}/results → résultats d'une tâche */
    @GetMapping("/tasks/{id}/results")
    public Mono<JsonNode> results(@PathVariable String id) {
        return openVasService.getResults(id);
    }

    /** GET /v1/infra/threat-intel?target=IP_or_domain → threat intelligence */
    @GetMapping("/threat-intel")
    public Mono<ObjectNode> threatIntel(@RequestParam String target) {
        return threatIntelService.check(target);
    }

    public record StartInfraScanRequest(String target, String name) {}
}