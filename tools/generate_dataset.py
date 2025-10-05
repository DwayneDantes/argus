# tools/generate_dataset.py
import argparse
import yaml
import logging
from generator.synthetic_dataset_generator import SyntheticDatasetGenerator

def setup_logging():
    """Sets up basic console logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def main():
    """CLI entrypoint for the dataset generator."""
    setup_logging()
    parser = argparse.ArgumentParser(description="Synthetic Dataset Generator for Project Argus")

    parser.add_argument(
        '--config',
        type=str,
        default='./config/generator_config.yaml',
        help='Path to the generator YAML config file.'
    )
    parser.add_argument(
        '--out',
        dest='sqlite_path',
        type=str,
        default=None, # Will use the path from the config if not provided
        help='Output path for the final dataset.sqlite file.'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=None, # Will use seed from config if not provided
        help='Random seed for reproducibility.'
    )
    parser.add_argument(
        '--use-cache',
        action='store_true',
        help='Load benign data from the local cache file specified in the config.'
    )
    parser.add_argument(
        '--force-refresh',
        action='store_true',
        help='Force a fresh fetch from the production DB, overwriting the local cache.'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Run the entire pipeline without writing any output files.'
    )

    args = parser.parse_args()

    # Load configuration from YAML file
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    # Override config with CLI arguments if they were provided
    sqlite_path = args.sqlite_path or config['output']['sqlite_path']
    seed = args.seed or config['random_seed']

    # Instantiate and run the generator
    generator = SyntheticDatasetGenerator(
        config=config,
        sqlite_path=sqlite_path,
        seed=seed,
        dry_run=args.dry_run
    )

    # --- THIS IS THE CORRECTED LINE ---
    generator.run(use_cache=args.use_cache, force_refresh=args.force_refresh)

if __name__ == '__main__':
    main()