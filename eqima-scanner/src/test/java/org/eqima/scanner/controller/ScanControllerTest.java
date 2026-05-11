package org.eqima.scanner.controller;

import org.eqima.scanner.dto.StartScanRequest;
import org.eqima.scanner.entity.ScanSession;
import org.eqima.scanner.service.ReportService;
import org.eqima.scanner.service.ScanService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@WebFluxTest(ScanController.class)
@Import(ScanControllerTest.TestSecurityConfig.class)
@TestPropertySource(properties = {
        "cors.allowed-origin=https://scanner.eqima.org",
        "zap.url=http://localhost",
        "zap.api-key=test-key"
})
class ScanControllerTest {

    @Autowired
    WebTestClient webTestClient;

    @MockBean
    ScanService scanService;

    @MockBean
    ReportService reportService;

    // ── POST /v1/scans ────────────────────────────────────────────────────────

    @Test
    void startScan_returns201_withSessionId() {
        ScanSession session = buildSession("abc-123", "volanaka");
        when(scanService.startScan(any())).thenReturn(Mono.just(session));

        webTestClient.post()
                .uri("/v1/scans")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new StartScanRequest("volanaka", null, null))
                .exchange()
                .expectStatus().isCreated()
                .expectBody()
                .jsonPath("$.id").isEqualTo("abc-123")
                .jsonPath("$.targetId").isEqualTo("volanaka")
                .jsonPath("$.status").isEqualTo("PENDING");
    }

    @Test
    void startScan_whenScanServiceFails_returns500() {
        when(scanService.startScan(any()))
                .thenReturn(Mono.error(new RuntimeException("ZAP unavailable")));

        webTestClient.post()
                .uri("/v1/scans")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(new StartScanRequest("volanaka", null, null))
                .exchange()
                .expectStatus().is5xxServerError();
    }

    // ── GET /v1/scans/{id} ────────────────────────────────────────────────────

    @Test
    void getSession_returns200() {
        ScanSession session = buildSession("xyz-456", "convergence");
        when(scanService.getSession("xyz-456")).thenReturn(Mono.just(session));

        webTestClient.get()
                .uri("/v1/scans/xyz-456")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.id").isEqualTo("xyz-456");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ScanSession buildSession(String id, String targetId) {
        ScanSession s = new ScanSession();
        s.setId(id);
        s.setTargetId(targetId);
        s.setTargetName("Test Target");
        s.setTargetUrl("https://example.com");
        s.setStatus(ScanSession.Status.PENDING);
        s.setStartedAt(Instant.now());
        s.setProgress(0);
        s.setTotalFindings(0);
        return s;
    }

    // Désactive la sécurité pour les tests unitaires du contrôleur
    @EnableWebFluxSecurity
    static class TestSecurityConfig {
        @Bean
        SecurityWebFilterChain testChain(ServerHttpSecurity http) {
            return http
                    .csrf(ServerHttpSecurity.CsrfSpec::disable)
                    .authorizeExchange(e -> e.anyExchange().permitAll())
                    .build();
        }
    }
}