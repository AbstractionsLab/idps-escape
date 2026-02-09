
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
ENV RADAR_FOLDAR=soar-radar

# Update and install depencencies + Create a non-root user
RUN apt update --fix-missing \
  && apt-get install -y git graphviz \
  && useradd -ms /bin/bash ${user} && echo '${user} ALL=(ALL) NOPASSWD:ALL' >>/etc/sudoers \
  && rm -rf /var/lib/apt/lists/*

# Install pipx
# RUN pip3 install pipenv
# Install Doorstop
RUN python3 -m pip install pipx \
  && python3 -m pipx ensurepath \
  && pip3 install poetry=="${POETRY_VERSION}" \
  && pipx install doorstop==3.0b10

# Add location where pip is installed to the PATH variable
ENV PATH="/home/${user}/.local/bin:${PATH}"

# Copy the files and install the python environment as user alab 
USER ${user} 

WORKDIR /home/${user}/${RADAR_FOLDAR}
RUN pwd
COPY --chown=${user}:${user} poetry.lock pyproject.toml /home/${user}/${RADAR_FOLDAR}/

# Project initialization
RUN poetry install --only radar

# Creating folders, and files for a project
COPY . /home/${user}/${RADAR_FOLDAR}

# Set the container starting point, running the project as the user
CMD ["poetry", "shell"]