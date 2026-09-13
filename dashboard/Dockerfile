FROM nginx:alpine

# Copy static dashboard files to Nginx web root
COPY index.html /usr/share/nginx/html/index.html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
