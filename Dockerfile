FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y nginx gettext-base && rm -rf /var/lib/apt/lists/*

# App
WORKDIR /app
COPY . /app

# Python deps (use requirements.txt if present)
RUN if [ -f requirements.txt ]; then \
      pip install --no-cache-dir -r requirements.txt ; \
    else \
      pip install --no-cache-dir streamlit==1.36.* pandas==2.* pillow==10.* bcrypt==4.* ; \
    fi

# Nginx template + start script
COPY render/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY render/start.sh /start.sh
RUN chmod +x /start.sh

# Streamlit listens on 10001; Nginx listens on $PORT (Render provides it)
ENV STREAMLIT_PORT=10001
EXPOSE 10001

CMD ["/bin/bash", "/start.sh"]
