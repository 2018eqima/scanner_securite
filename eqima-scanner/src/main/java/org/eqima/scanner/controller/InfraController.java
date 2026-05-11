package org.eqima.scanner.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.eqima.scanner.service.OpenVasService;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/v1/infra")
public class InfraController {

    private final OpenVasService openVasService;

    public InfraController(OpenVasService openVasService) {
        this.openVasService = openVasService;
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

    public record StartInfraScanRequest(String target, String name) {}
}