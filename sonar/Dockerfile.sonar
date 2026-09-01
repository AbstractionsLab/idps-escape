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

# Update and install dependencies
RUN apt update --fix-missing && \
    apt-get install -y git graphviz && \
    apt-get autoremove -y && apt-get autoclean -y && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -ms /bin/bash ${user} && echo '${user} ALL=(ALL) NOPASSWD:ALL' >>/etc/sudoers

# Add location where pip is installed to the PATH variable
ENV PATH="/home/${user}/.local/bin:${PATH}"

# Install poetry as user
USER ${user}
RUN pip3 install poetry=="${POETRY_VERSION}"

WORKDIR /home/${user}/${SOAR_FOLDER}
COPY --chown=${user}:${user} pyproject.toml poetry.lock /home/${user}/${SOAR_FOLDER}/

# Install dependencies (--no-root avoids errors when source not yet copied)
# RUN poetry install --no-root

# Copy project files
COPY --chown=${user}:${user} . /home/${user}/${SOAR_FOLDER}

# Install only SONAR dependencies
RUN poetry install --with sonar

RUN poetry install --only-root

# Install SONAR as editable package (creates sonar CLI entrypoint)
# RUN poetry install

# Set PYTHONPATH
ENV PYTHONPATH=/home/${user}/${SOAR_FOLDER}:${PYTHONPATH}

# Set the entrypoint to SONAR CLI
ENTRYPOINT ["poetry", "run", "python", "sonar/cli.py"]

# Default command (can be overridden)
CMD ["--help"]
