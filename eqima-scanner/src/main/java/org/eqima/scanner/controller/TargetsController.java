package org.eqima.scanner.controller;

import org.eqima.scanner.config.TargetsConfig;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.List;

@RestController
@RequestMapping("/v1/targets")
public class TargetsController {

    private final TargetsConfig targetsConfig;

    public TargetsController(TargetsConfig targetsConfig) {
        this.targetsConfig = targetsConfig;
    }

    /** GET /v1/targets → liste des cibles configurées dans application.yml */
    @GetMapping
    public Mono<List<TargetsConfig.Target>> getTargets() {
        return Mono.just(targetsConfig.getTargets());
    }
}