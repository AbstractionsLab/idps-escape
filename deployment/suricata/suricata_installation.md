# Installation and configuration of CyFORT-Suricata
The process of installing Suricata within a containerized environment consist of:

1. Install all [requirements](#requirements)
1. Pull [docker image](#suricata-docker-image) `Dockerfile` from the the folder [deployment/suricata](deployment/suricata)
1. Pull Suricata config file `suricata.yaml` and adapt Suricata config file to local network.
1. Build Docker Container
1. Run container

We advice to create a dedicate root folder to store docker image and docker file.

## Requirements
The following pieces of software are necessary for the installation of Suricata. 
1. [Docker Engine](https://docs.docker.com/engine/install/ubuntu/)  



## Suricata Docker Image 
In order to install Suricata inside a docker container, you will find a custom Dockerfile in this folder to build the Suricata docker image. An image is a read-only template with instructions for creating a Docker container. The approach to build a custom image is driven from the idea that we should be able to to control the privileges and capabilities we provide to this image for the purpose of security and minimization. 


## Suricata Configuration File
In order to configure Suricata container with the desired configurations instead of the default ones, we need to provide the suricata.yaml config file to the image which can also be seen in this directory. The image requires a suricata.yaml config file to be present in the same directory as the Dockerfile.  

However, the file still needs to be edited to provide the default host network interface since it would be different on different machines, on which we want to monitor the traffic, we configure the&nbsp;_af\_packet_ section of the configuration file.

To determine the device name of our default network interface.

```sh
ip -p -j route show default
```

Which gives the following output.

```sh
[ {
        "dst": "default",
        "gateway": "192.168.5.2",
        "dev": "enp7s0",
        "protocol": "static",
        "flags": [ ]
    } ] 
```

enp7s0 is the default network interface for our case. Change the interface name in suricata.yaml config file by using any sh editor. 

Find &quot;af-packet&quot; and replace the interface &quot;eth0&quot; with &quot;enp7s0&quot; or your default host network interface.

```sh
af_packet:  
    - interface: enp7s0
```

To enable pcap capture support on the monitor interface, add the interface name to the _pcap_ section and replace the interface &quot;eth0&quot; with &quot;enp7s0&quot; or your default host network interface.

```sh
pcap:  
    - interface: enp7s0 
```


In the same way  other configuration options can be set for other requirements. 

## Suricata Docker Container 
A container is a runnable instance of an image.  Since the Dockerfile uses the ubuntu image as the base image to build the Suricata image, it need to be fetched from the Docker Registry before building the container. A Docker registry stores Docker images. Docker Hub is a public registry that anyone can use, and Docker looks for images on Docker Hub by default.  This is done by the following command. 

### Build

```sh
sudo docker pull ubuntu
```

Using the docker client, the image is build and named as suricata-container.

```sh
sudo docker build -t suricata-container . 
```
### Run 

Run the container using the above created image.
The following command is to run the container creating a volume with it (this is necessary for IDPS-ESCAPE integration procedure). 

```sh
`sudo docker run -v /var/log/suricata:/var/log/suricata --network=host --hostname=suricata-instance --name=suricata-instance -d suricata-container`
```

The command line inside the container can be accessed by running the following command.

```sh
sudo docker exec -it suricata-instance bash
```

You can check if the container is running by 

```sh
sudo docker ps -a
```

##### Applying modifications

To modify the configuration file you can modify it in the built container, however this modification will not be persistent. Therefore, we suggest to apply modifications as above and restart the container with the modified file.