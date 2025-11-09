"""
HTTP communication service for password verification requests.

Implements IHttpClient interface with connection pooling and retry logic.

Author: Your Name
Date: 2025
"""

import time
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.interfaces import IHttpClient, TimingMeasurement
from core.exceptions import ConnectionFailedException
from utils.logger import Logger


class HttpClient(IHttpClient):
    """
    Robust HTTP client with connection pooling and automatic retries.

    Features:
    - Connection pooling for better performance
    - Automatic retry with exponential backoff
    - Precise timing measurements
    - Resource cleanup

    Example:
        >>> client = HttpClient("http://example.com", timeout=10)
        >>> measurement = client.send_request("password123", "user", 1)
        >>> print(f"Took {measurement.elapsed_time:.3f} seconds")
        >>> client.close()
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        max_retries: int = 3,
        pool_size: int = 10,
        logger: Optional[Logger] = None
    ):
        """
        Initialize HTTP client.

        Args:
            base_url: Base URL of the target server
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            pool_size: Size of connection pool
            logger: Optional logger instance
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.logger = logger or Logger()

        # Create session with connection pooling
        self.session = requests.Session()

        # Configure retry strategy
        # Note: method_whitelist was renamed to allowed_methods in urllib3 2.0+
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.3,  # Wait 0.3s, 0.6s, 1.2s between retries
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]  # Changed from method_whitelist
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
        Send a password verification request with precise timing.

        Args:
            password: Password candidate to test
            username: Username for authentication
            difficulty: Difficulty level

        Returns:
            TimingMeasurement object with timing and result data

        Raises:
            ConnectionFailedException: If unable to connect after retries
        """
        params = {
            'user': username,
            'password': password,
            'difficulty': difficulty
        }

        try:
            # Use perf_counter for precise timing (unaffected by system clock changes)
            start_time = time.perf_counter()

            response = self.session.get(
                self.base_url,
                params=params,
                timeout=self.timeout
            )

            elapsed_time = time.perf_counter() - start_time

            # Check if password is correct (server returns "1")
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

    def close(self) -> None:
        """Clean up session and release resources."""
        self.session.close()
        self.logger.info("HTTP client closed")