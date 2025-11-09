"""
HTTP Client: Network communication with timing measurements.
Simplified version without interfaces.
"""

import time
from dataclasses import dataclass
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils import Logger, ConnectionFailedException


# ============================================
# DATA CLASSES
# ============================================

@dataclass
class TimingMeasurement:
    """Result from a single timing measurement."""
    password: str
    elapsed_time: float
    success: bool = True
    is_correct: bool = False


# ============================================
# HTTP CLIENT
# ============================================

class HttpClient:
    """
    HTTP client with connection pooling and precise timing.

    Features:
    - Connection pooling for performance
    - Automatic retries with exponential backoff
    - Precise timing using perf_counter
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        max_retries: int = 3,
        pool_size: int = 10,
        logger: Optional[Logger] = None
    ):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.logger = logger or Logger()

        # Create session with connection pooling
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )

        adapter = HTTPAdapter(
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            max_retries=retry_strategy
        )

        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.logger.info(f"HTTP client initialized for {base_url}")

    def send_request(
        self,
        password: str,
        username: str,
        difficulty: int
    ) -> TimingMeasurement:
        """
        Send password verification request with precise timing.

        Args:
            password: Password to test
            username: Username
            difficulty: Difficulty level

        Returns:
            TimingMeasurement with timing data
        """
        params = {
            'user': username,
            'password': password,
            'difficulty': difficulty
        }

        try:
            # Precise timing (unaffected by system clock changes)
            start_time = time.perf_counter()

            response = self.session.get(
                self.base_url,
                params=params,
                timeout=self.timeout
            )

            elapsed_time = time.perf_counter() - start_time

            # Server returns "1" if password is correct
            is_correct = response.text.strip() == '1'

            self.logger.debug(
                f"Request: password='{password[:3]}...', "
                f"time={elapsed_time:.6f}s, correct={is_correct}"
            )

            return TimingMeasurement(
                password=password,
                elapsed_time=elapsed_time,
                success=True,
                is_correct=is_correct
            )

        except requests.exceptions.Timeout:
            self.logger.warning(f"Request timeout for password '{password[:3]}...'")
            return TimingMeasurement(
                password=password,
                elapsed_time=float('inf'),
                success=False
            )

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request failed: {str(e)}")
            raise ConnectionFailedException(self.base_url, str(e))

    def close(self):
        """Clean up session and release resources."""
        self.session.close()
        self.logger.info("HTTP client closed")
