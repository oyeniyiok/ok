FROM nginx:latest

COPY my-site/ /usr/share/nginx/html/

EXPOSE 80
