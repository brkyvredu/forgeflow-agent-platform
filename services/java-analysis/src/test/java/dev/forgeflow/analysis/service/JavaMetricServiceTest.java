package dev.forgeflow.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class JavaMetricServiceTest {
    private final JavaMetricService service = new JavaMetricService();

    @Test
    void extractsBoundedStructuralMetricsWithoutExecutingCode() {
        String source = """
                package demo;
                import java.util.List;
                public class Example {
                    // TODO improve
                    public int value(boolean enabled) {
                        if (enabled) { return 1; }
                        return 0;
                    }
                }
                """;

        JavaMetricService.JavaMetrics metrics = service.analyze(source);

        assertThat(metrics.importCount()).isEqualTo(1);
        assertThat(metrics.typeCount()).isEqualTo(1);
        assertThat(metrics.methodCount()).isEqualTo(1);
        assertThat(metrics.todoCount()).isEqualTo(1);
        assertThat(metrics.complexityEstimate()).isGreaterThanOrEqualTo(2);
        assertThat(metrics.maximumNesting()).isGreaterThanOrEqualTo(2);
    }

    @Test
    void doesNotCountControlFlowAsMethods() {
        String source = """
                class Example {
                    void run(boolean enabled) {
                        if (enabled) {
                            while (enabled) {
                                break;
                            }
                        }
                    }
                }
                """;

        var metrics = service.analyze(source);

        assertThat(metrics.methodCount()).isEqualTo(1);
    }

    @Test
    void flagsSelectedDangerousApis() {
        var metrics = service.analyze("class X { void x(){ new ProcessBuilder(); } }");
        assertThat(metrics.dangerousApis()).contains("ProcessBuilder");
    }
}
