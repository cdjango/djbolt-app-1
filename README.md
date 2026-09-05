# djbolt-app-1

```sh
uv lock --upgrade
uv sync --locked
uv run manage.py makemigrations auth core
uv run manage.py migrate
uv run manage.py createsuperuser --email admin@admin.com
uv run manage.py runbolt --dev
```
