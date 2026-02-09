
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

#ENV user=alab
ENV user=root
ENV ADBOX_FOLDER=adbox

# Update and install depencencies
RUN apt update --fix-missing
RUN apt-get install -y git python3-pip graphviz

# Create a non-root user
#RUN useradd -ms /bin/bash ${user} && echo '${user} ALL=(ALL) NOPASSWD:ALL' >>/etc/sudoers

# Add location where pip is installed to the PATH variable
ENV PATH="/home/${user}/.local/bin:${PATH}"

# Copy the files and install the python environment as user alab 
#USER ${user} 
# RUN pip3 install pipenv
RUN pip3 install poetry=="${POETRY_VERSION}"

WORKDIR /home/${user}/${ADBOX_FOLDER}
COPY poetry.lock pyproject.toml /home/${user}/${ADBOX_FOLDER}/

# Project initialization
RUN poetry install 

# RUN pip3 install torch

# Creating folders, and files for a project
COPY . /home/${user}/${ADBOX_FOLDER}

# Install python virtual environment for the project
WORKDIR /home/${user}/${ADBOX_FOLDER} 

# Set PYTHONPATH to include the project directory
ENV PYTHONPATH=/home/${user}/${ADBOX_FOLDER}:${PYTHONPATH} 

# Clean up unnecessary packages
#USER root
RUN apt-get autoremove -y && apt-get autoclean -y

# Set permissions for directories
#RUN  chown -R ${user}:${user} /home/${user}/${SIEM_MTAD_GAT_FOLDER} 

# Set the container starting point, running the project as the user
#USER ${user} 
# Set the entrypoint 
ENTRYPOINT ["poetry", "run", "pytest"]
#ENTRYPOINT ["poetry", "run", "python", "adbox"]

#CMD ["poetry", "shell"]
#CMD ["bash"]