Docker Build
------------

```
$ export SHOTGUN_VERSION=v20200914
$ docker build --no-cache -t registry.nic.cz/knot/shotgun:$SHOTGUN_VERSION --build-arg SHOTGUN_VERSION=$SHOTGUN_VERSION shotgun
$ docker build --no-cache -t registry.nic.cz/knot/shotgun/pellet:$SHOTGUN_VERSION --build-arg SHOTGUN_VERSION=$SHOTGUN_VERSION pellet

$ docker login registry.nic.cz
$ docker push registry.nic.cz/knot/shotgun:$SHOTGUN_VERSION
$ docker push registry.nic.cz/knot/shotgun/pellet:$SHOTGUN_VERSION
```
