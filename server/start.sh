docker run -it -d --restart=always -p 5000:5000 --name=secure_chat $(docker build -q .)
