import pytest

from lattice.storage import Storage


@pytest.fixture
def storage(tmp_path):
    """A fresh temporary database, closed automatically."""
    db = Storage(tmp_path / "test.db")
    yield db
    db.close()
