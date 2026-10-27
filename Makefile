# PromptShield developer shortcuts. Requires GNU make + Docker.
# (No make on Windows? Run the underlying commands shown after each target.)
.PHONY: up down logs test migrate seed demo-tamper ml-data ml-train ml-calibrate ml-train-tfidf

up:        ## build and start db + backend + frontend (backend migrates + seeds the admin on start)
	docker compose up --build -d

down:      ## stop everything (keeps the database volume)
	docker compose down

logs:      ## follow container logs
	docker compose logs -f

test:      ## run the backend test-suite inside the backend container
	docker compose run --rm --no-deps backend python -m pytest

migrate:   ## apply Alembic migrations to the compose database
	docker compose run --rm backend alembic upgrade head

seed:      ## create the admin user + target rows from ADMIN_EMAIL / ADMIN_PASSWORD
	docker compose run --rm backend python -m app.db.seed

demo-tamper: ## demo step 5: silently edit an audit row, then click "Verify chain" in the Admin page
	docker compose exec db sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -c "UPDATE audit_log SET action = '"'"'nothing_to_see_here'"'"' WHERE seq = 2;"'

# --- ML pipeline (runs on the host; see ml/requirements.txt) ---
ml-data:   ## build train/cal/test/OOD splits
	python ml/prepare_data.py

ml-train:  ## fine-tune microsoft/deberta-v3-small (GPU recommended)
	python ml/train_detector.py --backbone deberta

ml-train-tfidf: ## CPU-only TF-IDF + logistic-regression fallback detector
	python ml/train_detector.py --backbone tfidf

ml-calibrate: ## save calibration + test/OOD predictions for the conformal layer
	python ml/calibrate.py
