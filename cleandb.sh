rm -f ./db.sqlite3
find . -path "*/migrations/*.py" -not -path "*/.*" -not -name "__init__.py" -delete
find . -type d -name "__pycache__" -exec rm -rf {} +
echo "Database deleted. Press any key to continue making fresh database and migrations..."
read -n 1 -s
uv run manage.py makemigrations auth_app core
uv run manage.py migrate
uv run manage.py createsuperuser --email admin@admin.com
uv run manage.py runbolt --dev