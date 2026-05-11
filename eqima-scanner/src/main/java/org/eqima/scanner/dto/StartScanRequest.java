package org.eqima.scanner.dto;

public record StartScanRequest(
        String url,   // URL complète à scanner, ex: https://example.com
        String name   // Nom affiché (optionnel, déduit de l'URL si absent)
) {}