# Contributing to HEX IAM

Thank you for your interest in contributing! 

## How to Contribute

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR-USERNAME/hex-iam.git`
3. **Create a branch**: `git checkout -b feature/amazing-feature`
4. **Make your changes**
5. **Test** your changes: `pytest`
6. **Commit**: `git commit -m 'Add amazing feature'`
7. **Push**: `git push origin feature/amazing-feature`
8. **Open a Pull Request**

## Development Setup
```bash
# Install dependencies
poetry install

# Run tests
pytest

# Run linter
ruff check .

# Format code
black .
```

## Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public functions
- Keep functions small and focused (can be long if justified)

## Commit Messages

- Be descriptive but concise
- Reference issues when applicable

## Questions?

Open a [GitHub Discussion](https://github.com/Merrick1307/identity-access-management-system/discussions)