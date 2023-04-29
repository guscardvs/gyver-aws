.PHONY: format test setup-localstack-podman setup-localstack-docker

CONTAINER_NAME=localstack-container

format:
	@poetry run black gyver tests
	@poetry run isort -ir gyver tests
	@poetry run autoflake --remove-all-unused-imports --remove-unused-variables --remove-duplicate-keys --expand-star-imports -ir gyver tests

test:
	@poetry run pytest

setup-localstack-podman:
	@podman run \
		--rm -d \
		-p 4566:4566 \
		-p 4510-4559:4510-4559 \
		--name ${CONTAINER_NAME} \
		localstack/localstack

setup-localstack-docker:
	@docker run \
		--rm -d \
		-p 4566:4566 \
		-p 4510-4559:4510-4559 \
		--name ${CONTAINER_NAME} \
		localstack/localstack

teardown-localstack-podman:
	podman stop ${CONTAINER_NAME}
	podman rm -f ${CONTAINER_NAME}

teardown-localstack-docker:
	docker stop ${CONTAINER_NAME}
	docker rm -f${CONTAINER_NAME}