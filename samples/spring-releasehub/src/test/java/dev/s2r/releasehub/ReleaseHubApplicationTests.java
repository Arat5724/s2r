package dev.s2r.releasehub;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ReleaseHubApplicationTests {
    private final HttpClient client = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER).build();

    @LocalServerPort
    private int port;

    @Autowired
    private DataSource catalogDataSource;

    private HttpResponse<String> get(String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
    }

    private String query(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Test
    void servesSyntheticCatalogAndWebsite() throws Exception {
        assertEquals(200, get("/").statusCode());
        HttpResponse<String> response = get("/api/releases?q=Atlas");
        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("Atlas CLI"));
        assertFalse(response.body().contains("Beacon Gateway"));
        assertTrue(get("/api/summary").body().contains("releaseCount"));
    }

    @Test
    void sqlSearchIsInjectableButCatalogAccountCannotWrite() throws Exception {
        assertFalse(get("/api/releases?q=no-such-release").body().contains("Atlas CLI"));
        HttpResponse<String> injected = get("/api/releases?q=" + query("%' OR 1=1 -- "));
        assertEquals(200, injected.statusCode());
        assertTrue(injected.body().contains("Atlas CLI"));
        assertTrue(injected.body().contains("Beacon Gateway"));
        try (var connection = catalogDataSource.getConnection();
             var statement = connection.createStatement()) {
            assertThrows(SQLException.class, () -> statement.executeUpdate("DELETE FROM releases"));
        }
    }

    @Test
    void htmlPreviewReflectsHarmlessMarkup() throws Exception {
        String marker = "<strong data-s2r-probe=xss>releasehub-probe</strong>";
        HttpResponse<String> response = get("/search/preview?q=" + query(marker));
        assertEquals(200, response.statusCode());
        assertTrue(response.headers().firstValue("content-type").orElse("").contains("text/html"));
        assertTrue(response.body().contains(marker));
    }

    @Test
    void documentTraversalStaysWithinSyntheticFixtureRoot() throws Exception {
        assertTrue(get("/api/documents?name=release-guide.txt").body().contains("ReleaseHub field guide"));
        HttpResponse<String> canary = get("/api/documents?name=" + query("../private/canary.txt"));
        assertEquals(200, canary.statusCode());
        assertTrue(canary.body().contains("RELEASEHUB_PRIVATE_CANARY"));
        assertEquals(400, get("/api/documents?name=" + query("../../../outside.txt")).statusCode());
    }

    @Test
    void redirectOnlyReturnsLocationWithoutFollowingIt() throws Exception {
        String destination = "https://example.invalid/s2r-review-probe";
        HttpResponse<String> response = get("/go?next=" + query(destination));
        assertTrue(response.statusCode() >= 300 && response.statusCode() < 400);
        assertEquals(destination, response.headers().firstValue("location").orElse(""));
    }
}
