#!/usr/bin/env bash
set -e

# Streamlit will run on this internal port; Render provides $PORT for nginx to listen on.
export STREAMLIT_PORT="${STREAMLIT_PORT:-10001}"

# Fill the nginx template with env vars from Render and our STREAMLIT_PORT
envsubst '$PORT $STREAMLIT_PORT' \
  < /etc/nginx/templates/default.conf.template \
  > /etc/nginx/conf.d/default.conf

# Start Streamlit (background)
/usr/local/bin/streamlit run /app/app.py \
  --server.port "${STREAMLIT_PORT}" \
  --server.address 0.0.0.0 \
  --browser.gatherUsageStats false &

# Start nginx (foreground)
nginx -g 'daemon off;'
