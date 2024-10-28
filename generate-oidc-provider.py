import uuid
import json
import logging
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import argparse
import jwt
from pathlib import Path
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MockProvider:
    def __init__(self, prefix, base_url):
        self.prefix = prefix
        self.base_url = base_url.rstrip('/')  # Remove trailing slash if present
        self.private_key, self.public_key = self.generate_keypair()
        self.kid = str(uuid.uuid4())
        
    def generate_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def get_private_key_data(self):
        """Export private key data in PEM format"""
        private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return {
            "kid": self.kid,
            "private_key_pem": private_key_pem.decode('utf-8'),
            "issuer": f"{self.base_url}/{self.prefix}",
            "algorithm": "RS256"
        }

    def create_jwks(self):
        public_numbers = self.public_key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self.kid,
                    "use": "sig",
                    "n": self.int_to_base64(public_numbers.n),
                    "e": self.int_to_base64(public_numbers.e),
                    "alg": "RS256"
                }
            ]
        }

    @staticmethod
    def int_to_base64(value):
        """Convert an integer to a Base64URL-encoded string"""
        value_hex = format(value, 'x')
        if len(value_hex) % 2 == 1:
            value_hex = '0' + value_hex
        value_bytes = bytes.fromhex(value_hex)
        return jwt.utils.base64url_encode(value_bytes).decode('ascii')

    def get_oidc_config(self):
        issuer = f"{self.base_url}/{self.prefix}"
        return {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/jwks",
            "private_keys_uri": f"{issuer}/private-keys"
        }

def write_provider_files(provider, output_dir):
    """Write all OIDC configuration files for a provider to disk"""
    provider_dir = output_dir / provider.prefix
    provider_dir.mkdir(parents=True, exist_ok=True)
    
    # Create .well-known directory
    well_known_dir = provider_dir / '.well-known'
    well_known_dir.mkdir(exist_ok=True)
    
    # Write openid-configuration
    config_file = well_known_dir / 'openid-configuration'
    with open(config_file, 'w') as f:
        json.dump(provider.get_oidc_config(), f, indent=2)
    logger.info(f"Written: {config_file}")
    
    # Write JWKS
    jwks_file = provider_dir / 'jwks'
    with open(jwks_file, 'w') as f:
        json.dump(provider.create_jwks(), f, indent=2)
    logger.info(f"Written: {jwks_file}")
    
    # Write private keys
    private_keys_file = provider_dir / 'private-keys'
    with open(private_keys_file, 'w') as f:
        json.dump(provider.get_private_key_data(), f, indent=2)
    logger.info(f"Written: {private_keys_file}")
    
    # Set restrictive permissions on private keys file
    os.chmod(private_keys_file, 0o600)
    
def generate_oidc_files(base_url, num_providers):
    """Generate OIDC configuration files for multiple providers"""
    output_path = Path('.')  # Use current directory
    
    providers = []
    for _ in range(num_providers):
        prefix = str(uuid.uuid4())
        provider = MockProvider(prefix, base_url)
        providers.append(provider)
        write_provider_files(provider, output_path)
    
    # Write a summary file with all provider information
    summary = {
        "base_url": base_url,
        "providers": [
            {
                "prefix": p.prefix,
                "issuer": f"{base_url}/{p.prefix}",
                "config_path": f"{p.prefix}/.well-known/openid-configuration",
                "jwks_path": f"{p.prefix}/jwks",
                "private_keys_path": f"{p.prefix}/private-keys"
            }
            for p in providers
        ]
    }
    
    summary_file = output_path / 'providers-summary.json'
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    logger.info(f"Written summary to: {summary_file}")
    
    return providers

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate OIDC provider configuration files")
    parser.add_argument("--base-url", type=str, 
                      default="https://imduffy15.github.io/oidc-provider",
                      help="Base URL for the OIDC providers")
    parser.add_argument("--num-providers", type=int, default=1,
                      help="Number of providers to generate")
    
    args = parser.parse_args()
    
    providers = generate_oidc_files(args.base_url, args.num_providers)
    
    print("\nOIDC Provider files generated successfully!")
    print("\nDirectory structure:")
    for provider in providers:
        print(f"\n{provider.prefix}/")
        print(f"  ├── .well-known/")
        print(f"  │   └── openid-configuration")
        print(f"  ├── jwks")
        print(f"  └── private-keys")
    
    print("\nExample provider URLs:")
    print(f"OIDC Configuration: {args.base_url}/{providers[0].prefix}/.well-known/openid-configuration")
    print(f"JWKS Endpoint: {args.base_url}/{providers[0].prefix}/jwks")
    print(f"Private Keys: {args.base_url}/{providers[0].prefix}/private-keys")