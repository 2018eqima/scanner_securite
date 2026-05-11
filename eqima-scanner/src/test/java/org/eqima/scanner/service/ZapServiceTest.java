package org.eqima.scanner.service;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.eqima.scanner.entity.Finding;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ZapServiceTest {

    // ── mapAlert : mapping alerte ZAP → Finding ──────────────────────────────

    @Test
    void mapAlert_highRisk_mapsToHighSeverity() {
        ObjectNode alert = buildAlert("High", "SQL Injection",
                "https://example.com/login", "89", "Risque injection SQL", "Utiliser des requêtes préparées");

        Finding finding = ZapService.mapAlert(alert, "session-001");

        assertThat(finding.getSeverity()).isEqualTo(Finding.Severity.HIGH);
        assertThat(finding.getName()).isEqualTo("SQL Injection");
        assertThat(finding.getSessionId()).isEqualTo("session-001");
        assertThat(finding.getUrl()).isEqualTo("https://example.com/login");
        assertThat(finding.getCweid()).isEqualTo("89");
        assertThat(finding.getId()).isNotNull().isNotEmpty();
        assertThat(finding.getDetectedAt()).isNotNull();
    }

    @Test
    void mapAlert_mediumRisk_mapsToMediumSeverity() {
        ObjectNode alert = buildAlert("Medium", "XSS", "https://example.com/search", "79", "", "");
        Finding finding = ZapService.mapAlert(alert, "session-002");
        assertThat(finding.getSeverity()).isEqualTo(Finding.Severity.MEDIUM);
    }

    @Test
    void mapAlert_lowRisk_mapsToLowSeverity() {
        ObjectNode alert = buildAlert("Low", "Cookie sans Secure flag", "https://example.com", "614", "", "");
        Finding finding = ZapService.mapAlert(alert, "session-003");
        assertThat(finding.getSeverity()).isEqualTo(Finding.Severity.LOW);
    }

    @Test
    void mapAlert_informationalRisk_mapsToInformational() {
        ObjectNode alert = buildAlert("Informational", "Info leak", "https://example.com", "", "", "");
        Finding finding = ZapService.mapAlert(alert, "session-004");
        assertThat(finding.getSeverity()).isEqualTo(Finding.Severity.INFORMATIONAL);
    }

    @Test
    void mapAlert_unknownRisk_mapsToInformational() {
        ObjectNode alert = buildAlert("Unknown", "Mystery", "https://example.com", "", "", "");
        Finding finding = ZapService.mapAlert(alert, "session-005");
        assertThat(finding.getSeverity()).isEqualTo(Finding.Severity.INFORMATIONAL);
    }

    // ── mapSeverity ───────────────────────────────────────────────────────────

    @Test
    void mapSeverity_caseInsensitive() {
        assertThat(ZapService.mapSeverity("HIGH")).isEqualTo(Finding.Severity.HIGH);
        assertThat(ZapService.mapSeverity("high")).isEqualTo(Finding.Severity.HIGH);
        assertThat(ZapService.mapSeverity("High")).isEqualTo(Finding.Severity.HIGH);
        assertThat(ZapService.mapSeverity("MEDIUM")).isEqualTo(Finding.Severity.MEDIUM);
        assertThat(ZapService.mapSeverity("LOW")).isEqualTo(Finding.Severity.LOW);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private ObjectNode buildAlert(String risk, String name, String url,
                                  String cweid, String description, String solution) {
        JsonNodeFactory f = JsonNodeFactory.instance;
        ObjectNode node = f.objectNode();
        node.put("risk", risk);
        node.put("name", name);
        node.put("url", url);
        node.put("cweid", cweid);
        node.put("description", description);
        node.put("solution", solution);
        node.put("evidence", "");
        node.put("reference", "");
        node.put("wascid", "");
        return node;
    }
}