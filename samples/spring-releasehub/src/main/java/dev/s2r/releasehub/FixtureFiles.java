package dev.s2r.releasehub;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class FixtureFiles {
    private final Path root;

    public FixtureFiles() throws IOException {
        root = Files.createTempDirectory("s2r-releasehub-fixtures-").toRealPath();
        Files.createDirectories(root.resolve("public"));
        Files.createDirectories(root.resolve("private"));
        Files.writeString(root.resolve("public/release-guide.txt"),
            "ReleaseHub field guide\n\n제품 채널별 릴리스 기록과 버전을 확인할 수 있습니다.\n"
                + "검색 결과에서 제품을 선택하면 변경 요약이 열립니다.\n");
        Files.writeString(root.resolve("public/migration-notes.txt"),
            "Migration notes\n\nAtlas CLI 3.4: 배포 프로필을 다시 확인하세요.\n"
                + "Aster SDK 2.8: 스트리밍 이벤트 응답 형식을 확인하세요.\n");
        Files.writeString(root.resolve("private/canary.txt"),
            "RELEASEHUB_PRIVATE_CANARY\nThis file is synthetic training data.\n");
    }

    public Path resolve(String name) {
        Path target = root.resolve("public").resolve(name).normalize();
        if (!target.startsWith(root)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        }
        return target;
    }
}
