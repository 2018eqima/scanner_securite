package org.eqima.scanner.controller;

import org.eqima.scanner.service.SubdomainDiscoveryService;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/subdomains")
public class SubdomainController {

    private final SubdomainDiscoveryService discoveryService;

    public SubdomainController(SubdomainDiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
    }

    /** GET /v1/subdomains/discover?domain=eqima.org */
    @GetMapping("/discover")
    public Mono<List<Map<String, Object>>> discover(@RequestParam String domain) {
        return discoveryService.discover(domain);
    }
}