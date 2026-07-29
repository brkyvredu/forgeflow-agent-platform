package dev.forgeflow.analysis.api;

import dev.forgeflow.analysis.service.JavaMetricService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/java")
public class JavaAnalysisController {
    private final JavaMetricService metricService;

    public JavaAnalysisController(JavaMetricService metricService) {
        this.metricService = metricService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<JavaMetricService.JavaMetrics> analyze(@Valid @RequestBody AnalyzeRequest request) {
        return ResponseEntity.ok(metricService.analyze(request.sourceCode()));
    }

    public record AnalyzeRequest(
            @NotBlank @Size(max = 200_000) String sourceCode
    ) { }
}
