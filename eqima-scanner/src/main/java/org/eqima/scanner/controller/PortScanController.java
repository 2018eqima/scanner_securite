package org.eqima.scanner.controller;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.eqima.scanner.service.PortScanService;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/v1/ports")
public class PortScanController {

    private final PortScanService portScanService;

    public PortScanController(PortScanService portScanService) {
        this.portScanService = portScanService;
    }

    /** GET /v1/ports/scan?target=IP_or_domain */
    @GetMapping("/scan")
    public Mono<ObjectNode> scan(@RequestParam String target) {
        return portScanService.scan(target);
    }
}