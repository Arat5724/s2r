from review import main


def test_techlab_is_the_default_project(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    data.mkdir()
    monkeypatch.setattr(main, 'DATA', data)

    rows = main.projects()

    assert rows == [
        {'id': 'techlab', 'name': 'TechLab', 'path': str(main.TECHLAB)},
        {'id': 'spring-releasehub', 'name': 'ReleaseHub (Spring Boot)',
         'path': str(main.SPRING_SAMPLE)},
    ]
    assert main.read_json(data / 'projects.json') == rows
    assert main.TECHLAB.parent / 'techlab-runtime' in main.PROTECTED
    assert main.SPRING_SAMPLE.parent / 'spring-releasehub-runtime' in main.PROTECTED


def test_builtin_teamshelf_migrates_without_removing_custom_projects_or_jobs(tmp_path, monkeypatch):
    data = tmp_path / 'data'
    (data / 'jobs' / 'historical-job').mkdir(parents=True)
    monkeypatch.setattr(main, 'DATA', data)
    custom = {'id': 'custom-project', 'name': 'My Project', 'path': str(tmp_path / 'custom')}
    separately_added_teamshelf = {'id': 'my-teamshelf', 'name': 'My TeamShelf', 'path': str(main.SAMPLE)}
    original = {'id': 'teamshelf', 'name': 'TeamShelf', 'path': str(main.SAMPLE)}
    main.write_json(data / 'projects.json', [original, custom, separately_added_teamshelf])

    rows = main.projects()

    assert [row['id'] for row in rows] == [
        'techlab', 'spring-releasehub', 'custom-project', 'my-teamshelf']
    assert rows[2:] == [custom, separately_added_teamshelf]
    assert main.read_json(data / 'projects.json') == rows
    assert main.projects() == rows
    assert (data / 'jobs' / 'historical-job').is_dir()


def test_spring_sample_defaults_to_its_local_port(tmp_path):
    job = tmp_path / 'job'
    job.mkdir()
    main.write_json(job / 'status.json', {'project': {'id': 'spring-releasehub'}})
    assert main.selection(job)['target_base_url'] == 'http://127.0.0.1:8030'
