FROM python:3.13-slim

WORKDIR /app

RUN pip install poetry --no-cache-dir

RUN poetry config virtualenvs.create false

COPY pyproject.toml poetry.lock /app/

RUN poetry install --no-root

COPY . .

EXPOSE 8000

ENTRYPOINT ["poetry", "run", "python", "-m", "app.main"]