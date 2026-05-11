package org.eqima.scanner.dto;

import java.util.List;

public record StartScanRequest(
        String targetId,
        List<String> selectedUrls,   // null = toutes les URLs de la cible
        List<String> modules          // null = modules par défaut de la cible
) {}