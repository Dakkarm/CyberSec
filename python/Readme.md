
Be sure that the the entire folder has the right permissions.
To do it, open the terminal and write
    chmod -R +rx ./

REMEMBER: do this operation for every exercise.

To execute the exercise, do the following on the terminal

  sudo ./docker_build.sh

and then

  sudo ./docker_run.sh

Check inside docker_run the ip:port to use (in this case 127.0.0.1:2052)

Alternatively you can use the following commands:

# Build

```bash
docker build -t registry.insecurity-insa.fr/insecurity/python .
```

# Run

```bash
docker run -it \
           -d --restart=always \
           --name python \
           -p 2052:5000 \
           --cpu-period="100000" --cpu-quota="90000" \
           --ulimit nproc=1024:1024 \
           --ulimit fsize=10000:10000 \
           --ulimit data=1000000:1000000 \
           registry.insecurity-insa.fr/insecurity/python
docker stop python && docker rm -v python
docker exec -u 0 -it python bash
```
# Errors

If you receive this error in the build phase:

    ERROR: failed to solve: python:3.9: error getting credentials - err: exit status 1, out: ``

Try to run the following command:

    sudo docker pull python:3.9