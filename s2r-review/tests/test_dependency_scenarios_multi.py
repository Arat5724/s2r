from review.dependency_scenarios import build_dependency_scenarios


def test_non_pypi_advisories_keep_manifest_line_and_ecosystem():
    files = {
        'package.json': '{\n  "dependencies": {"express": "4.21.0"}\n}\n',
        'pom.xml': '<project><dependencies><dependency>\n<groupId>org.example</groupId>\n<artifactId>core</artifactId>\n<version>1.2.3</version>\n</dependency></dependencies></project>',
        'build.gradle': "dependencies { implementation 'org.example:extra:2.0.0' }\n",
        'composer.json': '{\n  "require": {"laravel/framework": "11.0.0"}\n}\n',
    }
    pins = [('npm', 'express', '4.21.0', 'package.json'),
            ('Maven', 'org.example:core', '1.2.3', 'pom.xml'),
            ('Maven', 'org.example:extra', '2.0.0', 'build.gradle'),
            ('Packagist', 'laravel/framework', '11.0.0', 'composer.json')]
    audit = {'packages': [{'ecosystem': ecosystem, 'name': name, 'version': version,
                           'source_files': [file], 'advisories': [{'id': 'OSV-TEST'}]}
                          for ecosystem, name, version, file in pins]}
    scenarios = build_dependency_scenarios(audit, files)
    assert len(scenarios) == len(pins)
    assert len({row['id'] for row in scenarios}) == len(pins)
    for scenario, (ecosystem, name, version, file) in zip(scenarios, pins):
        assert scenario['source_evidence'][0]['file'] == file
        assert scenario['source_evidence'][0]['line'] > 0
        assert ecosystem in scenario['source_trigger']
        assert name in scenario['title'] and version in scenario['title']
        assert not scenario['automatable']
