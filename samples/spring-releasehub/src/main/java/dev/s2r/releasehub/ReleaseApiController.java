package dev.s2r.releasehub;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@RestController
public class ReleaseApiController {
    private final JdbcTemplate jdbcTemplate;
    private final FixtureFiles fixtureFiles;

    public ReleaseApiController(JdbcTemplate jdbcTemplate, FixtureFiles fixtureFiles) {
        this.jdbcTemplate = jdbcTemplate;
        this.fixtureFiles = fixtureFiles;
    }

    public record Release(String id, String name, String channel, String version,
                          String shippedOn, String summary) {}

    @GetMapping("/api/releases")
    public Map<String, Object> releases(@RequestParam(name = "q", required = false, defaultValue = "") String q) {
        List<Release> items = jdbcTemplate.query(
            "SELECT id, name, channel, version, shipped_on, summary FROM releases "
                + "WHERE name ILIKE '%" + q + "%' ORDER BY shipped_on DESC",
            (rs, row) -> new Release(rs.getString("id"), rs.getString("name"),
                rs.getString("channel"), rs.getString("version"),
                rs.getString("shipped_on"), rs.getString("summary")));
        return Map.of("items", items, "total", items.size());
    }

    @GetMapping("/api/summary")
    public Map<String, Object> summary() {
        return Map.of("releaseCount", 6, "channels", 4,
            "latestVersion", "3.4.2", "latestProduct", "Atlas CLI");
    }

    @GetMapping(value = "/api/documents", produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> document(@RequestParam(value = "name", required = false,
            defaultValue = "release-guide.txt") String name) throws IOException {
        try {
            return ResponseEntity.ok(new String(Files.readAllBytes(fixtureFiles.resolve(name)), StandardCharsets.UTF_8));
        } catch (NoSuchFileException missing) {
            throw new ResponseStatusException(NOT_FOUND);
        }
    }
}
