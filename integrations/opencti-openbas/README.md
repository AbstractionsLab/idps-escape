# OpenCTI Installation

Deploying OpenCTI with docker requires cloning its repository and changing a few environment variables (in `.env`):

```bash
mkdir -p /opencti && cd /opencti
git clone https://github.com/OpenCTI-Platform/docker.git
cd docker
mv .env.sample .env
nano .env  # Change and adjust environmental variables according to requirement and preferences.
docker-compose up -d
```

# OpenBAS Installation

To deploy OpenBAS in Docker, clone the repository and also change a few environment variables:

```bash
mkdir -p /openbas && cd /openbas
git clone https://github.com/OpenBAS-Platform/docker.git
cd docker
mv .env.sample .env
nano .env # Change and adjust environmental variables according to requirement and preferences.
docker-compose up -d
```

### Troubleshooting

**Note**: If you are installing OpenBAS and OpenCTI in one local environment, change ports of conflicting services!

Also, to solve conflicts in RabbitMQ services, it was removed from both `docker-compose.yml` files. Instead, separate RabbitMQ services were created with two Vhosts for OpenCTI and OpenBAS:

```yaml
version: '3.8'

services:
  rabbitmq:
    image: rabbitmq:4.0-management
    container_name: rabbitmq
    hostname: rabbitmq
    restart: always
    networks:
      - opencti-wazuh-network
    environment:
      - RABBITMQ_DEFAULT_USER=admin
      - RABBITMQ_DEFAULT_PASS=SuperSecurePass!
    ports:
      - "5672:5672"  # AMQP
      - "15672:15672" # Management UI
    volumes:
      - rabbitmqdata:/var/lib/rabbitmq
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  opencti-wazuh-network:
    external: true

volumes:
  rabbitmqdata:
```

After deploying the service, the following commands will configure vhost creation and user accounts creation with permissions:

```bash
docker exec -it rabbitmq rabbitmqctl add_vhost opencti
docker exec -it rabbitmq rabbitmqctl add_vhost openbas
docker exec -it rabbitmq rabbitmqctl add_user opencti StrongPassword123!
docker exec -it rabbitmq rabbitmqctl add_user openbas AnotherStrongPass!
docker exec -it rabbitmq rabbitmqctl set_user_tags opencti administrator
docker exec -it rabbitmq rabbitmqctl set_user_tags openbas administrator
docker exec -it rabbitmq rabbitmqctl set_permissions -p opencti opencti ".*" ".*" ".*"
docker exec -it rabbitmq rabbitmqctl set_permissions -p openbas openbas ".*" ".*" ".*"
```

Adjust environment variables `.env` in OpenCTI and OpenBAS:

```bash
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=StrongPassword123!
RABBITMQ_DEFAULT_VHOST=opencti
```

```bash
RABBITMQ_DEFAULT_USER=openbas
RABBITMQ_DEFAULT_PASS=AnotherStrongPass!
RABBITMQ_DEFAULT_VHOST=openbas
```

Edit environment variables in `docker-compose.yml` files in OpenBAS and OpenCTI:

```yaml
environment:
  - RABBITMQ_DEFAULT_USER=${RABBITMQ_DEFAULT_USER}
  - RABBITMQ_DEFAULT_PASS=${RABBITMQ_DEFAULT_PASS}
  - RABBITMQ_DEFAULT_VHOST=${RABBITMQ_DEFAULT_VHOST}
```

# OpenBAS and OpenCTI integration

For integrating both services, environment variables are added to `docker-compose.yml`. In OpenCTI, references to OpenBAS are added:

```yaml
- XTM__OPENBAS_URL=http://openbas:8080
- XTM__OPENBAS_TOKEN=${XTM__OPENBAS_TOKEN}
- XTM__OPENBAS_TIMEOUT=60000
```

In OpenBAS, references to OpenCTI are added:

```yaml
- OPENBAS_XTM_OPENCTI_TOKEN=${OPENBAS_XTM_OPENCTI_TOKEN}
- OPENBAS_XTM_OPENCTI_ENABLE=${OPENBAS_XTM_OPENCTI_ENABLE}
- OPENBAS_XTM_OPENCTI_URL=${OPENBAS_XTM_OPENCTI_URL}
```

According to these new variables, the `.env` file is adjusted in both systems.

### Troubleshooting

1.  Error querying OpenBAS.
    
This error is shown when the “Simulate” button in OpenCTI is pressed.

The error indicates that the connection with OpenBAS is not instantiated. It can be because of the user tokens or incorrect URLs. It may also be due to port misconfigurations. If both systems are run locally in one machine, make sure ports for OpenCTI and OpenBAS services are configured without causing conflicts.

### docker-compose

Adapted to the integration, ready-to-use `docker-compose.yml` files can be found in this repository.