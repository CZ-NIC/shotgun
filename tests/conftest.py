"""Enable pytest assertion diffs in shared test helpers."""

import pytest

pytest.register_assert_rewrite("common")
