from PIL import Image
import imagehash
import io
from pathlib import Path
import pytest


def pytest_addoption(parser):
    parser.addoption("--update-baselines", action="store_true")


@pytest.fixture
def visual_compare(request):
    baseline_dir = Path("baselines")
    baseline_dir.mkdir(exist_ok=True)
    update = request.config.getoption("--update-baselines")

    def compare(screenshot_bytes, name):
        baseline_path = baseline_dir / f"{name}.png"
        current = Image.open(io.BytesIO(screenshot_bytes))

        if update or not baseline_path.exists():
            current.save(baseline_path)
            if not update:
                pytest.skip(f"Baseline created: {name}")
            return

        baseline = Image.open(baseline_path)
        diff = imagehash.average_hash(current) - imagehash.average_hash(baseline)
        assert diff < 1, f"Visual diff: {diff}"

    return compare
