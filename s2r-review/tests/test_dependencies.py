import json

from review.dependencies import audit_dependencies


def recorded_results(seen, advisories=None):
    def fetch(payload):
        seen.append(payload)
        ids = advisories or {}
        return {'results': [{'vulns': [{'id': value} for value in ids.get(
            (query['package']['ecosystem'], query['package']['name']), [])]}
            for query in payload['queries']]}
    return fetch


def test_npm_direct_exact_pins_only_and_scoped_package():
    seen = []
    content = json.dumps({
        'dependencies': {'express': '4.21.2', '@nestjs/common': '10.4.5',
                         'range': '^1.2.3', 'remote': 'https://private.invalid/archive.tgz',
                         'alias': 'npm:express@4.21.2', 'local': 'workspace:*'},
        'devDependencies': {'express': '4.21.2', 'typescript': '5.7.3'},
    }, indent=2)
    audit = audit_dependencies({'package.json': content}, recorded_results(seen))
    assert seen == [{'queries': [
        {'package': {'ecosystem': 'npm', 'name': 'express'}, 'version': '4.21.2'},
        {'package': {'ecosystem': 'npm', 'name': '@nestjs/common'}, 'version': '10.4.5'},
        {'package': {'ecosystem': 'npm', 'name': 'typescript'}, 'version': '5.7.3'},
    ]}]
    assert len(audit['packages']) == 3
    assert audit['packages'][0]['source_files'] == ['package.json']
    assert len(audit['unresolved']) == 4
    assert audit['status'] == 'partial'
    assert 'private.invalid' not in json.dumps(seen)


def test_maven_namespaced_pom_uses_direct_concrete_dependencies_only():
    seen = []
    content = '''<project xmlns="http://maven.apache.org/POM/4.0.0">
      <dependencyManagement><dependencies><dependency>
        <groupId>org.example</groupId><artifactId>managed</artifactId><version>1.0.0</version>
      </dependency></dependencies></dependencyManagement>
      <dependencies>
        <dependency><groupId>org.springframework.boot</groupId>
          <artifactId>spring-boot-starter-web</artifactId><version>3.3.5</version></dependency>
        <dependency><groupId>org.example</groupId><artifactId>property</artifactId>
          <version>${revision}</version></dependency>
        <dependency><groupId>org.example</groupId><artifactId>snapshot</artifactId>
          <version>1.0.0-SNAPSHOT</version></dependency>
        <dependency><groupId>org.example</groupId><artifactId>inherited</artifactId></dependency>
      </dependencies>
    </project>'''
    audit = audit_dependencies({'pom.xml': content}, recorded_results(seen))
    assert seen == [{'queries': [{'package': {'ecosystem': 'Maven',
                         'name': 'org.springframework.boot:spring-boot-starter-web'},
                         'version': '3.3.5'}]}]
    assert len(audit['unresolved']) == 3
    assert audit['packages'][0]['source_files'] == ['pom.xml']


def test_composer_exact_require_and_require_dev_only():
    seen = []
    content = json.dumps({'require': {'laravel/framework': '11.12.0', 'php': '^8.2',
                                      'vendor/ranged': '~1.0.0',
                                      'vendor/from-repo': 'dev-main'},
                          'require-dev': {'phpunit/phpunit': '11.0.0'}})
    audit = audit_dependencies({'composer.json': content}, recorded_results(seen, {
        ('Packagist', 'laravel/framework'): ['GHSA-test-1234']}))
    assert seen == [{'queries': [
        {'package': {'ecosystem': 'Packagist', 'name': 'laravel/framework'}, 'version': '11.12.0'},
        {'package': {'ecosystem': 'Packagist', 'name': 'phpunit/phpunit'}, 'version': '11.0.0'},
    ]}]
    assert audit['packages'][0]['advisories'][0]['id'] == 'GHSA-test-1234'
    assert audit['packages'][0]['source_files'] == ['composer.json']
    assert len(audit['unresolved']) == 3


def test_custom_registry_repository_and_requirements_include_are_not_queried():
    seen = []
    files = {
        'package.json': json.dumps({'config': {'registry': 'https://private.invalid/npm'},
                                    'dependencies': {'secret-name': '1.2.3'}}),
        'pom.xml': '''<project><repositories><repository><url>https://private.invalid/maven</url>
          </repository></repositories><dependencies><dependency><groupId>secret</groupId>
          <artifactId>artifact</artifactId><version>1.0.0</version></dependency></dependencies></project>''',
        'composer.json': json.dumps({'repositories': [{'type': 'vcs',
                              'url': 'https://private.invalid/composer'}],
                              'require': {'secret/package': '1.0.0'}}),
        'requirements.txt': '-r private-requirements.txt\nsecret==1.0\n',
    }
    audit = audit_dependencies(files, recorded_results(seen))
    assert not seen and not audit['packages']
    assert audit['status'] == 'partial'
    assert len(audit['unresolved']) == 4
    assert 'private.invalid' not in json.dumps(audit)


def test_mixed_ecosystems_keep_distinct_source_files_and_failed_manifests_do_not_block():
    seen = []
    files = {
        'requirements.txt': 'shared==1.0.0\n',
        'frontend/package.json': '{"dependencies":{"shared":"1.0.0"}}',
        'site/package.json': '{"dependencies":{"shared":"1.0.0"}}',
        'broken/composer.json': '{not json',
    }
    audit = audit_dependencies(files, recorded_results(seen))
    assert len(seen[0]['queries']) == 2
    assert [row['ecosystem'] for row in audit['packages']] == ['PyPI', 'npm']
    assert audit['packages'][1]['source_files'] == ['frontend/package.json', 'site/package.json']
    assert audit['status'] == 'partial'
    assert audit['unresolved'][0]['file'] == 'broken/composer.json'


def test_maven_dtd_is_rejected_without_fetching():
    seen = []
    audit = audit_dependencies({'pom.xml': '<!DOCTYPE project [<!ENTITY x "secret">]><project />'},
                               recorded_results(seen))
    assert not seen and not audit['packages']
    assert 'DTD' in audit['unresolved'][0]['reason']


def test_gradle_groovy_and_kotlin_literal_dependencies_use_maven_ecosystem():
    seen = []
    files = {
        'service/build.gradle': '''repositories { mavenCentral() }
            dependencies {
              implementation 'org.springframework.boot:spring-boot-starter-web:3.3.5'
              testImplementation 'org.junit.jupiter:junit-jupiter:5.11.0'
              implementation "org.example:ranged:$version"
              implementation project(':local')
            }''',
        'worker/build.gradle.kts': '''repositories { mavenCentral() }
            dependencies {
              implementation("org.springframework.boot:spring-boot-starter-web:3.3.5")
              implementation(libs.jackson)
              implementation("org.example:dynamic:1.0.0-SNAPSHOT")
            }''',
    }
    audit = audit_dependencies(files, recorded_results(seen))
    assert seen == [{'queries': [
        {'package': {'ecosystem': 'Maven',
                     'name': 'org.springframework.boot:spring-boot-starter-web'}, 'version': '3.3.5'},
        {'package': {'ecosystem': 'Maven', 'name': 'org.junit.jupiter:junit-jupiter'},
         'version': '5.11.0'},
    ]}]
    assert audit['packages'][0]['source_files'] == ['service/build.gradle', 'worker/build.gradle.kts']
    assert len(audit['unresolved']) == 4


def test_gradle_custom_repository_is_not_queried():
    seen = []
    audit = audit_dependencies({'build.gradle.kts': '''repositories {
        maven { url = uri("https://private.invalid/maven") }
        mavenCentral()
      }
      dependencies { implementation("secret:package:1.0.0") }'''}, recorded_results(seen))
    assert not seen and not audit['packages']
    assert len(audit['unresolved']) == 1
    assert 'private.invalid' not in json.dumps(audit)
