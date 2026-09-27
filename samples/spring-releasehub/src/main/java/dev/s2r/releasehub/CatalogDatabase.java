package dev.s2r.releasehub;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration
public class CatalogDatabase {
    private static final String URL = "jdbc:h2:mem:releasehub;DB_CLOSE_DELAY=-1";

    // Bootstrap uses an admin connection once. Web requests use only the SELECT-granted user.
    @Bean
    public DataSource catalogDataSource() throws SQLException {
        try (Connection admin = DriverManager.getConnection(URL, "sa", "");
             Statement setup = admin.createStatement()) {
            setup.execute("CREATE TABLE IF NOT EXISTS releases (id VARCHAR(12) PRIMARY KEY, "
                + "name VARCHAR(100), channel VARCHAR(30), version VARCHAR(30), "
                + "shipped_on DATE, summary VARCHAR(300))");
            setup.execute("DELETE FROM releases");
            try (PreparedStatement seed = admin.prepareStatement(
                    "INSERT INTO releases (id, name, channel, version, shipped_on, summary) "
                        + "VALUES (?, ?, ?, ?, ?, ?)")) {
                Object[][] rows = {
                    {"rh-101", "Atlas CLI", "Developer tools", "3.4.2", "2026-09-18", "배포 프로필을 하나로 정리하고 로컬 미리보기 시작 시간을 단축했습니다."},
                    {"rh-102", "Aster Java SDK", "SDK", "2.8.0", "2026-09-12", "스트리밍 이벤트 처리와 타입이 지정된 오류 응답을 추가했습니다."},
                    {"rh-103", "Orbit UI Kit", "Design system", "5.1.3", "2026-09-04", "내비게이션의 키보드 접근성과 컴포넌트 안내를 개선했습니다."},
                    {"rh-104", "Beacon Gateway", "Infrastructure", "1.9.1", "2026-08-27", "요청 추적 기능과 정책 기반 라우팅 규칙을 추가했습니다."},
                    {"rh-105", "Quill Docs API", "SDK", "4.0.0", "2026-08-14", "문서 검색 결과를 개선하고 내보내기 옵션을 확장했습니다."},
                    {"rh-106", "Northstar Metrics", "Infrastructure", "2.2.6", "2026-08-06", "서비스 상태 화면과 알림 요약을 새로 제공합니다."}
                };
                for (Object[] row : rows) {
                    for (int index = 0; index < row.length; index++) {
                        seed.setObject(index + 1, row[index]);
                    }
                    seed.addBatch();
                }
                seed.executeBatch();
            }
            setup.execute("CREATE USER IF NOT EXISTS release_reader PASSWORD 'local-synthetic-only'");
            setup.execute("GRANT SELECT ON releases TO release_reader");
        }
        DriverManagerDataSource reader = new DriverManagerDataSource();
        reader.setDriverClassName("org.h2.Driver");
        // The admin connection configures DB_CLOSE_DELAY once; a non-admin user
        // cannot set this database-wide option on each later connection.
        reader.setUrl("jdbc:h2:mem:releasehub");
        reader.setUsername("release_reader");
        reader.setPassword("local-synthetic-only");
        return reader;
    }
}
