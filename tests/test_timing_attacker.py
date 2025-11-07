"""
Unit tests for timing attack components.

Run with: pytest tests/test_timing_attacker.py -v

Author: Your Name
Date: 2025
"""

import pytest
from unittest.mock import Mock, MagicMock
from src.core.interfaces import TimingMeasurement, CharacterAnalysis
from src.services.analysis_service import AnalysisService
from src.utils.stats import remove_outliers, is_significantly_different
from src.utils.logger import Logger


class TestStatisticalFunctions:
    """Test suite for statistical utility functions."""

    def test_remove_outliers_basic(self):
        """Test outlier removal with obvious outliers."""
        data = [1.0, 1.1, 1.0, 1.2, 10.0, 1.1]  # 10.0 is outlier
        cleaned = remove_outliers(data, std_dev_threshold=2.0)

        assert 10.0 not in cleaned
        assert len(cleaned) == 5

    def test_remove_outliers_no_outliers(self):
        """Test outlier removal with clean data."""
        data = [1.0, 1.1, 1.0, 1.2, 1.1]
        cleaned = remove_outliers(data)

        assert len(cleaned) == len(data)

    def test_is_significantly_different(self):
        """Test statistical significance detection."""
        fast = [0.1, 0.11, 0.09, 0.1, 0.11]
        slow = [0.2, 0.21, 0.19, 0.2, 0.21]

        is_different, p_value = is_significantly_different(fast, slow)

        assert is_different is True
        assert p_value < 0.05


class TestAnalysisService:
    """Test suite for timing analysis service."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance for tests."""
        logger = Logger(console=False)
        return AnalysisService(logger=logger)

    def test_analyze_measurements_basic(self, analyzer):
        """Test basic measurement analysis."""
        measurements = [
            TimingMeasurement("abc", 0.1, True, False),
            TimingMeasurement("abc", 0.11, True, False),
            TimingMeasurement("abc", 0.09, True, False),
        ]

        analysis = analyzer.analyze_measurements(measurements)

        assert analysis.character == 'c'
        assert 0.08 < analysis.median_time < 0.12
        assert analysis.sample_size == 3

    def test_analyze_measurements_with_outlier(self, analyzer):
        """Test analysis with outlier removal."""
        measurements = [
            TimingMeasurement("xyz", 0.1, True, False),
            TimingMeasurement("xyz", 0.11, True, False),
            TimingMeasurement("xyz", 5.0, True, False),  # Outlier
            TimingMeasurement("xyz", 0.09, True, False),
        ]

        analysis = analyzer.analyze_measurements(measurements)

        # Outlier should be removed
        assert analysis.median_time < 0.5

    def test_compare_candidates(self, analyzer):
        """Test candidate comparison and selection."""
        analyses = [
            CharacterAnalysis('a', 0.1, 0.1, 0.01, 0.9, 20),
            CharacterAnalysis('b', 0.2, 0.2, 0.01, 0.9, 20),  # Longest time
            CharacterAnalysis('c', 0.15, 0.15, 0.01, 0.9, 20),
        ]

        best_char, confidence = analyzer.compare_candidates(analyses)

        assert best_char == 'b'  # Longest time wins
        assert confidence > 0.5


class TestTimingMeasurement:
    """Test timing measurement data model."""

    def test_create_measurement(self):
        """Test measurement creation."""
        m = TimingMeasurement(
            password="test",
            elapsed_time=0.123,
            success=True,
            is_correct=False
        )

        assert m.password == "test"
        assert m.elapsed_time == 0.123
        assert m.success is True
        assert m.is_correct is False


class TestIntegration:
    """Integration tests for complete attack flow."""

    @pytest.fixture
    def mock_http_client(self):
        """Create mock HTTP client."""
        client = Mock()

        # Simulate correct character taking longer
        def side_effect(password, username, difficulty):
            # Character 'h' takes 0.2s, others take 0.1s
            if password.endswith('h'):
                return TimingMeasurement(password, 0.2, True, False)
            else:
                return TimingMeasurement(password, 0.1, True, False)

        client.send_request.side_effect = side_effect
        return client

    def test_character_discovery(self, mock_http_client):
        """Test discovering a character through timing differences."""
        from src.services.timing_service import TimingService, SamplingStrategy

        logger = Logger(console=False)
        strategy = SamplingStrategy(
            initial_samples=5,
            middle_samples=5,
            final_samples=5,
            min_samples=3
        )

        service = TimingService(mock_http_client, strategy, logger)

        # Measure candidates
        results = service.measure_all_candidates(
            current_password="",
            charset="abch",  # Include 'h' which should be slower
            username="test",
            difficulty=1,
            position=0
        )

        # Analyze results
        analyzer = AnalysisService(logger=logger)
        analyses = []

        for char, measurements in results.items():
            analysis = analyzer.analyze_measurements(measurements)
            analyses.append(analysis)

        best_char, _ = analyzer.compare_candidates(analyses)

        # Should discover 'h' as the correct character (longest time)
        assert best_char == 'h'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])