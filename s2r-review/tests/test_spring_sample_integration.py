"""The Spring training service reaches the model as original source text."""

from pathlib import Path

from ai_source import prepare_source
from review.snapshot import snapshot


SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "spring-releasehub"


def test_spring_sample_route_handlers_are_visible_to_model():
    files = snapshot(SAMPLE)['files']
    assert 'pom.xml' in files
    java_files = {name: source for name, source in files.items() if name.endswith('.java')}
    assert java_files
    source_text, shown, _, _ = prepare_source(files)
    assert any(name in {path for path, _ in shown} for name in java_files)
    assert '@GetMapping' in source_text
    assert '/api/releases' in source_text
