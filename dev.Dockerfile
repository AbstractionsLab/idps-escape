
FROM python:3.10.12

ARG MY_ENV

ENV MY_ENV=${MY_ENV} \
  PYTHONFAULTHANDLER=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  POETRY_VERSION=1.5.0

ENV user=alab
ENV SOAR_FOLDER=soar

# Install system dependencies, Node.js 20, and Chromium in a single layer;
# clean up APT cache immediately to avoid baking it into the image
RUN apt-get update --fix-missing \
  && apt-get install -y --no-install-recommends git python3-pip graphviz curl ca-certificates \
  && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
  && apt-get install -y --no-install-recommends nodejs \
  && apt-get install -y --no-install-recommends chromium || apt-get install -y --no-install-recommends chromium-browser || true \
  && apt-get autoremove -y \
  && apt-get autoclean -y \
  && rm -rf /var/lib/apt/lists/*

# Install Mermaid CLI (global, system-level; runs as root)
RUN npm install -g @mermaid-js/mermaid-cli

# Create a non-root user (no sudo granted)
RUN useradd -ms /bin/bash ${user}

# Add location where pip/pipx install user-scoped tools to the PATH
ENV PATH="/home/${user}/.local/bin:${PATH}"

# Switch to non-root user for all subsequent steps
USER ${user}

# Install pipx and poetry under the user account
RUN python3 -m pip install --no-cache-dir pipx \
  && python3 -m pipx ensurepath \
  && pip3 install --no-cache-dir poetry=="${POETRY_VERSION}"

WORKDIR /home/${user}/${SOAR_FOLDER}
COPY --chown=${user}:${user} poetry.lock pyproject.toml /home/${user}/${SOAR_FOLDER}/

# Project initialization
RUN poetry install --only docs --no-root

# Copy project files with correct ownership
COPY --chown=${user}:${user} . /home/${user}/${SOAR_FOLDER}

# Install Doorstop
RUN pipx install doorstop==3.0b10

CMD ["poetry", "shell"]